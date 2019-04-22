/*
Copyright (C)  2018 Yahoo Japan Corporation Athenz team.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/kpango/gache"
	"github.com/kpango/glg"
	"github.com/pkg/errors"
	"github.com/yahoo/athenz/utils/zpe-updater/util"
	"github.com/yahoojapan/athenz-policy-updater/pubkey"
	"golang.org/x/sync/errgroup"
)

// Policyd represent the daemon to retrieve policy data from Athenz.
type Policyd interface {
	StartPolicyUpdater(context.Context) <-chan error
	UpdatePolicy(context.Context) error
	CheckPolicy(ctx context.Context, domain string, roles []string, action, resource string) error
}

type policyd struct {
	expireMargin     time.Duration // expire margin force update policy when the policy expire time hit the margin
	rolePolicies     gache.Gache   //*sync.Map // map[<domain>:role.<role>][]Assertion
	refreshDuration  time.Duration
	errRetryInterval time.Duration

	pkp pubkey.Provider

	etagCache    gache.Gache
	etagFlushDur time.Duration
	etagExpTime  time.Duration

	// www.athenz.com/zts/v1
	athenzURL     string
	athenzDomains []string

	client *http.Client
}

type etagCache struct {
	eTag string
	sp   *SignedPolicy
}

// NewPolicyd represent the constructor of Policyd
func NewPolicyd(opts ...Option) (Policyd, error) {
	p := &policyd{
		rolePolicies: gache.New(),
		etagCache:    gache.New(),
	}

	p.rolePolicies.EnableExpiredHook().SetExpiredHook(func(ctx context.Context, key string) {
		//key = <domain>:role.<role>
		p.fetchAndCachePolicy(ctx, strings.Split(key, ":role.")[0])
	})

	for _, opt := range append(defaultOptions, opts...) {
		err := opt(p)
		if err != nil {
			return nil, errors.Wrap(err, "error create policyd")
		}
	}

	return p, nil
}

// StartPolicyUpdater starts the Policy daemon to retrive the policy data periodically
func (p *policyd) StartPolicyUpdater(ctx context.Context) <-chan error {
	glg.Info("Starting policyd updater")
	ech := make(chan error, 100)
	fch := make(chan struct{}, 1)
	if err := p.UpdatePolicy(ctx); err != nil {
		ech <- errors.Wrap(err, "error update policy")
		fch <- struct{}{}
	}

	go func() {
		defer close(fch)
		defer close(ech)
		p.etagCache.StartExpired(ctx, p.etagFlushDur)
		p.rolePolicies.StartExpired(ctx, time.Hour*24)
		ticker := time.NewTicker(p.refreshDuration)
		ebuf := errors.New("")
		for {
			select {
			case <-ctx.Done():
				glg.Info("Stopping policyd updater")
				ticker.Stop()
				ech <- ctx.Err()
				if ebuf.Error() != "" {
					ech <- errors.Wrap(ctx.Err(), ebuf.Error())
				} else {
					ech <- ctx.Err()
				}
				return
			case <-fch:
				if err := p.UpdatePolicy(ctx); err != nil {
					err = errors.Wrap(err, "error update policy")
					select {
					case ech <- errors.Wrap(ebuf, err.Error()):
						ebuf = errors.New("")
					default:
						ebuf = errors.Wrap(ebuf, err.Error())
					}
					time.Sleep(p.errRetryInterval)
					select {
					case fch <- struct{}{}:
					default:
						glg.Warn("failure queue already full")
					}
				}
			case <-ticker.C:
				if err := p.UpdatePolicy(ctx); err != nil {
					err = errors.Wrap(err, "error update policy")
					select {
					case ech <- errors.Wrap(ebuf, err.Error()):
						ebuf = errors.New("")
					default:
						ebuf = errors.Wrap(ebuf, err.Error())
					}
					select {
					case fch <- struct{}{}:
					default:
						glg.Warn("failure queue already full")
					}
				}
			}
		}
	}()

	return ech
}

// UpdatePolicy updates and cache policy data
func (p *policyd) UpdatePolicy(ctx context.Context) error {
	glg.Info("Updating policy")
	defer glg.Info("Updated policy")
	eg := errgroup.Group{}

	for _, domain := range p.athenzDomains {
		select {
		case <-ctx.Done():
			glg.Info("Update policy interrupted")
			return ctx.Err()
		default:
			dom := domain
			eg.Go(func() error {
				select {
				case <-ctx.Done():
					glg.Info("Update policy interrupted")
					return ctx.Err()
				default:
					return p.fetchAndCachePolicy(ctx, dom)
				}
			})
		}
	}

	return eg.Wait()
}

// CheckPolicy checks the specified request has privilege to access the resources or not.
// If return is nil then the request is allowed, otherwise the request is rejected.
func (p *policyd) CheckPolicy(ctx context.Context, domain string, roles []string, action, resource string) error {
	ech := make(chan error, 1)
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		defer close(ech)
		wg := new(sync.WaitGroup)
		for _, role := range roles {
			dr := fmt.Sprintf("%s:role.%s", domain, role)
			wg.Add(1)
			go func(ch chan<- error) {
				defer wg.Done()
				select {
				case <-cctx.Done():
					ch <- cctx.Err()
					return
				default:
					asss, ok := p.rolePolicies.Get(dr)
					if !ok {
						return
					}

					for _, ass := range asss.([]*Assertion) {
						glg.Debugf("Checking policy domain: %s, role: %v, action: %s, resource: %s, assertion: %v", domain, roles, action, resource, ass)
						select {
						case <-cctx.Done():
							ch <- cctx.Err()
							return
						default:
							if strings.EqualFold(ass.ResourceDomain, domain) && ass.Reg.MatchString(strings.ToLower(action+"-"+resource)) {
								ch <- ass.Effect
								return
							}
						}
					}
				}
			}(ech)
		}
		wg.Wait()
		ech <- errors.Wrap(ErrNoMatch, "no match")
	}()

	err := <-ech

	glg.Debugf("check policy domain: %s, role: %v, action: %s, resource: %s, result: %v", domain, roles, action, resource, err)
	return err
}

func (p *policyd) fetchAndCachePolicy(ctx context.Context, dom string) error {
	spd, upd, err := p.fetchPolicy(ctx, dom)
	if err != nil {
		return errors.Wrap(err, "error fetch policy")
	}

	if upd {
		if glg.Get().GetCurrentMode(glg.DEBG) != glg.NONE {
			rawpol, _ := json.Marshal(spd)
			glg.Debugf("fetched policy data:\tdomain\t%s\tbody\t%s", dom, (string)(rawpol))
		}

		if err = p.simplifyAndCache(ctx, spd); err != nil {
			return errors.Wrap(err, "error simplify and cache")
		}
	}

	return nil
}

func (p *policyd) fetchPolicy(ctx context.Context, domain string) (*SignedPolicy, bool, error) {
	glg.Infof("Fetching policy for domain %s", domain)
	// https://{www.athenz.com/zts/v1}/domain/{athenz domain}/signed_policy_data
	url := fmt.Sprintf("https://%s/domain/%s/signed_policy_data", p.athenzURL, domain)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		glg.Errorf("Fetch policy error, domain: %s, error: %v", domain, err)
		return nil, false, errors.Wrap(err, "error creating fetch policy request")
	}

	// etag header
	t, ok := p.etagCache.Get(domain)
	if ok {
		ec := t.(*etagCache)
		if time.Now().Add(p.expireMargin).UnixNano() < ec.sp.SignedPolicyData.Expires.UnixNano() {
			glg.Debugf("domain : %s, using etag: %s", domain, ec.eTag)
			req.Header.Set("If-None-Match", ec.eTag)
		}
	}

	res, err := p.client.Do(req.WithContext(ctx))
	if err != nil {
		glg.Errorf("Error making HTTP request, domain: %s, error: %v", domain, err)
		return nil, false, errors.Wrap(err, "error making request")
	}

	// if server return NotModified, return policy from cache
	if res.StatusCode == http.StatusNotModified {
		cache := t.(*etagCache)
		glg.Debugf("Server return not modified, domain: %s, etag: %v", domain, cache.eTag)
		return cache.sp, false, nil
	}

	if res.StatusCode != http.StatusOK {
		glg.Errorf("Domain %s: Server return not OK", domain)
		return nil, false, errors.Wrap(ErrFetchPolicy, "error fetching policy data")
	}

	// read and decode
	sp := new(SignedPolicy)
	if err = json.NewDecoder(res.Body).Decode(&sp); err != nil {
		glg.Errorf("Error decoding policy, domain: %s, err: %v", domain, err)
		return nil, false, errors.Wrap(err, "error decode response")
	}

	// verify policy data
	if err = sp.Verify(p.pkp); err != nil {
		glg.Errorf("Error verifing policy, domain: %s,err: %v", domain, err)
		return nil, false, errors.Wrap(err, "error verify policy data")
	}

	if _, err = io.Copy(ioutil.Discard, res.Body); err != nil {
		glg.Warn(errors.Wrap(err, "error io.copy"))
	}
	if err = res.Body.Close(); err != nil {
		glg.Warn(errors.Wrap(err, "error body.close"))
	}

	// set eTag cache
	eTag := res.Header.Get("ETag")
	if eTag != "" {
		glg.Debugf("Setting ETag %v for domain %s", eTag, domain)
		p.etagCache.SetWithExpire(domain, &etagCache{eTag, sp}, p.etagExpTime)
	}

	return sp, true, nil
}

func (p *policyd) simplifyAndCache(ctx context.Context, sp *SignedPolicy) error {
	rp := gache.New()
	defer rp.Clear()

	eg := errgroup.Group{}
	mu := new(sync.Mutex)
	assm := new(sync.Map)
	for _, policy := range sp.DomainSignedPolicyData.SignedPolicyData.PolicyData.Policies {
		pol := policy
		eg.Go(func() error {
			for _, ass := range pol.Assertions {
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
					km := fmt.Sprintf("%s,%s,%s", ass.Role, ass.Action, ass.Resource)
					if _, ok := assm.Load(km); !ok {
						assm.Store(km, ass)
					} else {
						if strings.EqualFold("deny", ass.Effect) {
							assm.Store(km, ass)
						}
					}

				}
			}

			return nil
		})
	}

	if err := eg.Wait(); err != nil {
		return errors.Wrap(err, "error simplify and cache policy")
	}

	var retErr error
	assm.Range(func(k interface{}, val interface{}) bool {
		ass := val.(*util.Assertion)
		a, err := NewAssertion(ass.Action, ass.Resource, ass.Effect)
		if err != nil {
			retErr = err
			return false
		}
		var asss []*Assertion

		mu.Lock()
		if r, ok := rp.Get(ass.Role); ok {
			asss = append(r.([]*Assertion), a)
		} else {
			asss = []*Assertion{a}
		}
		rp.SetWithExpire(ass.Role, asss, time.Duration(sp.DomainSignedPolicyData.SignedPolicyData.Expires.UnixNano()))
		mu.Unlock()
		return true
	})
	if retErr != nil {
		return retErr
	}

	rp.Foreach(ctx, func(k string, val interface{}, exp int64) bool {
		p.rolePolicies.SetWithExpire(k, val, time.Duration(exp))
		return true
	})

	p.rolePolicies.Foreach(ctx, func(k string, val interface{}, exp int64) bool {
		_, ok := rp.Get(k)
		if !ok {
			p.rolePolicies.Delete(k)
		}
		return true
	})

	return nil
}