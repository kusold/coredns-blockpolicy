package blockpolicy

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coredns/caddy"
)

func TestParseConfig(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	denyFile := filepath.Join(tmp, "deny.txt")
	if err := os.WriteFile(denyFile, []byte("ads.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	corefile := `.:53 {
		blockpolicy {
			policy default {
				deny_groups ads
				block_mode zeroip
				ttl 30s
			}
			use_policy default
			list_group ads {
				source ` + denyFile + `
				format auto
			}
			loading {
				refresh_period 4h
				startup_timeout 20s
				http_timeout 5s
				max_body_size 1024
			}
			matching {
				exact true
				wildcard false
				regex false
				hosts_format true
				deep_cname true
				response_ip_lists true
			}
		}
	}`

	c := caddy.NewTestController("dns", corefile)

	cfg, err := parseConfig(c)
	if err != nil {
		t.Fatalf("parseConfig failed: %v", err)
	}
	if cfg.PolicyName != "default" {
		t.Fatalf("expected default policy, got %q", cfg.PolicyName)
	}
	if cfg.Policy.Mode != modeZeroIP {
		t.Fatalf("expected zeroip mode")
	}
	if cfg.Loading.RefreshPeriod.String() != "4h0m0s" {
		t.Fatalf("unexpected refresh_period: %s", cfg.Loading.RefreshPeriod)
	}
	if !cfg.Matching.Exact || cfg.Matching.Wildcard {
		t.Fatalf("unexpected matching config: %+v", cfg.Matching)
	}
}

func TestSetupSucceedsWithValidConfig(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	denyFile := filepath.Join(tmp, "deny.txt")
	if err := os.WriteFile(denyFile, []byte("ads.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	corefile := `.:53 {
		blockpolicy {
			policy default {
				deny_groups ads
				block_mode zeroip
			}
			use_policy default
			list_group ads {
				source ` + denyFile + `
				format auto
			}
			loading {
				refresh_period 4h
				startup_timeout 1s
				http_timeout 1s
				max_body_size 1024
			}
		}
	}`

	c := caddy.NewTestController("dns", corefile)
	if err := setup(c); err != nil {
		t.Fatalf("expected setup to succeed, got error: %v", err)
	}
}

func TestParseConfigUsePolicyMismatch(t *testing.T) {
	t.Parallel()
	corefile := `.:53 {
		blockpolicy {
			policy default {
				deny_groups ads
			}
			use_policy other
			list_group ads {
				source /tmp/ads.txt
			}
		}
	}`

	c := caddy.NewTestController("dns", corefile)
	if _, err := parseConfig(c); err == nil {
		t.Fatalf("expected parseConfig to fail on use_policy mismatch")
	}
}

func TestParseConfigUnknownTopLevelDirective(t *testing.T) {
	t.Parallel()
	corefile := `.:53 {
		blockpolicy {
			unknown true
		}
	}`

	c := caddy.NewTestController("dns", corefile)
	if _, err := parseConfig(c); err == nil {
		t.Fatalf("expected unknown directive error")
	}
}

func TestParsePolicyRequiresDenyGroup(t *testing.T) {
	t.Parallel()
	corefile := `.:53 {
		blockpolicy {
			policy default {
				block_mode zeroip
			}
			use_policy default
		}
	}`

	c := caddy.NewTestController("dns", corefile)
	if _, err := parseConfig(c); err == nil {
		t.Fatalf("expected missing deny_groups to fail")
	}
}

func TestParseConfigErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		corefile string
		wantErr  string
	}{
		{
			name: "invalid block mode",
			corefile: `.:53 {
				blockpolicy {
					policy default {
						deny_groups ads
						block_mode nope
					}
					use_policy default
					list_group ads {
						source /tmp/ads.txt
					}
				}
			}`,
			wantErr: `unsupported block_mode`,
		},
		{
			name: "invalid ttl",
			corefile: `.:53 {
				blockpolicy {
					policy default {
						deny_groups ads
						ttl notaduration
					}
					use_policy default
					list_group ads {
						source /tmp/ads.txt
					}
				}
			}`,
			wantErr: `invalid ttl`,
		},
		{
			name: "invalid refresh period",
			corefile: `.:53 {
				blockpolicy {
					policy default {
						deny_groups ads
					}
					use_policy default
					list_group ads {
						source /tmp/ads.txt
					}
					loading {
						refresh_period nope
					}
				}
			}`,
			wantErr: `invalid refresh_period`,
		},
		{
			name: "invalid startup timeout",
			corefile: `.:53 {
				blockpolicy {
					policy default {
						deny_groups ads
					}
					use_policy default
					list_group ads {
						source /tmp/ads.txt
					}
					loading {
						startup_timeout nope
					}
				}
			}`,
			wantErr: `invalid startup_timeout`,
		},
		{
			name: "invalid http timeout",
			corefile: `.:53 {
				blockpolicy {
					policy default {
						deny_groups ads
					}
					use_policy default
					list_group ads {
						source /tmp/ads.txt
					}
					loading {
						http_timeout nope
					}
				}
			}`,
			wantErr: `invalid http_timeout`,
		},
		{
			name: "invalid max body size",
			corefile: `.:53 {
				blockpolicy {
					policy default {
						deny_groups ads
					}
					use_policy default
					list_group ads {
						source /tmp/ads.txt
					}
					loading {
						max_body_size noint
					}
				}
			}`,
			wantErr: `invalid max_body_size`,
		},
		{
			name: "invalid matching bool",
			corefile: `.:53 {
				blockpolicy {
					policy default {
						deny_groups ads
					}
					use_policy default
					list_group ads {
						source /tmp/ads.txt
					}
					matching {
						exact notabool
					}
				}
			}`,
			wantErr: `invalid bool value for "exact"`,
		},
		{
			name: "unknown policy directive",
			corefile: `.:53 {
				blockpolicy {
					policy default {
						deny_groups ads
						nope true
					}
					use_policy default
					list_group ads {
						source /tmp/ads.txt
					}
				}
			}`,
			wantErr: `unknown policy directive`,
		},
		{
			name: "unknown list group directive",
			corefile: `.:53 {
				blockpolicy {
					policy default {
						deny_groups ads
					}
					use_policy default
					list_group ads {
						nope true
					}
				}
			}`,
			wantErr: `unknown list_group directive`,
		},
		{
			name: "unknown loading directive",
			corefile: `.:53 {
				blockpolicy {
					policy default {
						deny_groups ads
					}
					use_policy default
					list_group ads {
						source /tmp/ads.txt
					}
					loading {
						nope true
					}
				}
			}`,
			wantErr: `unknown loading directive`,
		},
		{
			name: "unknown matching directive",
			corefile: `.:53 {
				blockpolicy {
					policy default {
						deny_groups ads
					}
					use_policy default
					list_group ads {
						source /tmp/ads.txt
					}
					matching {
						nope true
					}
				}
			}`,
			wantErr: `unknown matching directive`,
		},
		{
			name: "list group missing source",
			corefile: `.:53 {
				blockpolicy {
					policy default {
						deny_groups ads
					}
					use_policy default
					list_group ads {
						format auto
					}
				}
			}`,
			wantErr: `requires at least one source`,
		},
		{
			name: "empty policy name",
			corefile: `.:53 {
				blockpolicy {
					policy {
						deny_groups ads
					}
					use_policy default
					list_group ads {
						source /tmp/ads.txt
					}
				}
			}`,
			wantErr: `expecting argument`,
		},
		{
			name: "missing closing brace policy",
			corefile: `.:53 {
				blockpolicy {
					policy default {
						deny_groups ads
						ttl 30s`,
			wantErr: `Unexpected EOF`,
		},
		{
			name: "logging unsupported",
			corefile: `.:53 {
				blockpolicy {
					policy default {
						deny_groups ads
					}
					use_policy default
					list_group ads {
						source /tmp/ads.txt
					}
					logging {
						blocked true
					}
				}
			}`,
			wantErr: `logging block not yet supported`,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := caddy.NewTestController("dns", tt.corefile)
			_, err := parseConfig(c)
			if err == nil {
				t.Fatalf("expected parseConfig to fail")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %q", tt.wantErr, err.Error())
			}
		})
	}
}

func TestSetupFailsWhenInitialLoadExceedsStartupTimeout(t *testing.T) {
	t.Parallel()

	requestStarted := make(chan struct{}, 1)
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case requestStarted <- struct{}{}:
		default:
		}
		<-release
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ads.example\n"))
	}))
	defer srv.Close()

	corefile := `.:53 {
		blockpolicy {
			policy default {
				deny_groups ads
			}
			use_policy default
			list_group ads {
				source ` + srv.URL + `
				format auto
			}
			loading {
				refresh_period 4h
				startup_timeout 50ms
				http_timeout 1s
				max_body_size 1024
			}
		}
	}`

	c := caddy.NewTestController("dns", corefile)
	errCh := make(chan error, 1)
	go func() {
		errCh <- setup(c)
	}()

	select {
	case <-requestStarted:
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for list request to start")
	}

	var err error
	select {
	case err = <-errCh:
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for setup to fail")
	}
	close(release)

	if err == nil {
		t.Fatalf("expected setup to fail due to startup timeout")
	}
}
