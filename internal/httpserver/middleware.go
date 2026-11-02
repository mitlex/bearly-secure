//lint:file-ignore U1000 Some code in this file is used later

package httpserver

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bootdotdev/learn-web-security/internal/httpx"
	"github.com/bootdotdev/learn-web-security/internal/logging"
	"github.com/bootdotdev/learn-web-security/internal/templates"
)

type middleware func(http.Handler) http.Handler

func applyMiddleware(handler http.Handler, middlewareChain ...middleware) http.Handler {
	for _, currentMiddleware := range slices.Backward(middlewareChain) {
		handler = currentMiddleware(handler)
	}
	return handler
}

func securityHeaders(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		nonce := httpx.CSPNonce(request.Context())
		responseWriter.Header().Set(
			"Content-Security-Policy", // one layer of defense against XSS by restricting allowed script/style/resource sources
			fmt.Sprintf("default-src 'self'; script-src 'self' 'nonce-%s'; style-src 'self'; img-src 'self' data:; frame-src 'self'; frame-ancestors 'self'; object-src 'none'; base-uri 'self'; form-action 'self'", nonce))
		responseWriter.Header().Set("X-Frame-Options", "SAMEORIGIN")                      // prevents clickjacking via iframe embedding
		responseWriter.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin") // limits URL info leaked in Referer header
		responseWriter.Header().Set("X-Content-Type-Options", "nosniff")                  // stops MIME-type sniffing attacks
		responseWriter.Header().Set("Cross-Origin-Opener-Policy", "same-origin")          // isolates browsing context from cross-origin openers
		responseWriter.Header().Set("Cross-Origin-Resource-Policy", "same-origin")        // blocks other origins from loading Bearly Secure's resources
		responseWriter.Header().Set("Origin-Agent-Cluster", "?1")                         // requests origin-keyed process isolation
		responseWriter.Header().Set("X-DNS-Prefetch-Control", "off")                      // disables speculative DNS prefetching
		responseWriter.Header().Set("X-Download-Options", "noopen")                       // (legacy IE) forces save instead of auto-open on download
		responseWriter.Header().Set("X-Permitted-Cross-Domain-Policies", "none")          // (legacy Flash/PDF) blocks cross-domain policy files
		responseWriter.Header().Set("X-XSS-Protection", "0")                              // disables obsolete/unreliable browser XSS filter
		handler.ServeHTTP(responseWriter, request)
	})
}

func allowCrossOriginWidgetAssets(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		responseWriter.Header().Set("Cross-Origin-Resource-Policy", "cross-origin") // enables other origins to load Bearly Secure's resources
		handler.ServeHTTP(responseWriter, request)
	})
}

func globalSourceValidationMiddleware(appOrigin string, renderer *templates.Renderer) middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
			if request.Method != http.MethodPost {
				next.ServeHTTP(responseWriter, request)
				return
			}
			trusted := false
			requestOrigin := request.Header.Get("Origin")
			if requestOrigin == appOrigin {
				trusted = true
			}
			if requestOrigin == "" {
				refererURL, err := url.Parse(request.Header.Get("Referer"))
				if err == nil && appOrigin == refererURL.Scheme+"://"+refererURL.Host {
					trusted = true
				}
			}
			if trusted {
				next.ServeHTTP(responseWriter, request)
				return
			}
			if err := httpx.RespondWithErrorPage(responseWriter, renderer, http.StatusForbidden, "Request Blocked", "We couldn't verify that this request came from Bearly Secure"); err != nil {
				http.Error(responseWriter, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
		})
	}
}

func cspNonce(next http.Handler) http.Handler {
	return http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		nonceBytes := make([]byte, 16)
		if _, err := rand.Read(nonceBytes); err != nil {
			http.Error(responseWriter, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		nonce := base64.StdEncoding.EncodeToString(nonceBytes)
		request = request.WithContext(httpx.WithCSPNonce(request.Context(), nonce))
		next.ServeHTTP(responseWriter, request)
	})
}

func recoverPanics(logger *logging.Logger, renderer *templates.Renderer) middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
			defer func() {
				if recovered := recover(); recovered != nil {
					_ = logger.Event("unhandled_error", map[string]any{
						"method":  request.Method,
						"path":    request.URL.Path,
						"message": fmt.Sprint(recovered),
					})
					if err := httpx.RespondWithErrorPage(responseWriter, renderer, http.StatusInternalServerError, "Unhandled Error", fmt.Sprint(recovered)); err != nil {
						http.Error(responseWriter, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					}
				}
			}()
			next.ServeHTTP(responseWriter, request)
		})
	}
}

func LoadShedder(_ int, _ int) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return next
	}
}

func SearchThrottle(_ *templates.Renderer) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return next
	}
}

type rateLimitCounter struct {
	count   int
	resetAt time.Time
}

type rateLimitOptions struct {
	window  time.Duration
	maximum int
	key     func(*http.Request) string
	onLimit func(http.ResponseWriter, *http.Request, rateLimitState)
	now     func() time.Time
}

type rateLimitState struct {
	limit             int
	remaining         int
	resetAt           time.Time
	retryAfterSeconds int
}

type fixedWindowLimiter struct {
	options       rateLimitOptions
	counters      map[string]rateLimitCounter
	countersMutex sync.Mutex
	nextSweepAt   time.Time
}

func newFixedWindowLimiter(options rateLimitOptions) *fixedWindowLimiter {
	validateRateLimitOptions(options)
	if options.now == nil {
		options.now = time.Now
	}
	if options.key == nil {
		options.key = clientIPKey
	}
	return &fixedWindowLimiter{
		options:     options,
		counters:    make(map[string]rateLimitCounter),
		nextSweepAt: options.now().Add(options.window),
	}
}

func validateRateLimitOptions(options rateLimitOptions) {
	if options.window <= 0 {
		panic("rate-limit window must be positive")
	}
	if options.maximum <= 0 {
		panic("rate-limit maximum must be positive")
	}
}

func (limiter *fixedWindowLimiter) consume(request *http.Request) (rateLimitState, bool) {
	now := limiter.options.now()
	key := limiter.options.key(request)

	limiter.countersMutex.Lock()
	defer limiter.countersMutex.Unlock()
	limiter.sweepExpiredCounters(now)

	counter, exists := limiter.counters[key]
	if !exists || !now.Before(counter.resetAt) {
		counter = rateLimitCounter{resetAt: now.Add(limiter.options.window)}
	}
	retryAfterSeconds := max(1, int(math.Ceil(counter.resetAt.Sub(now).Seconds())))
	if counter.count >= limiter.options.maximum {
		return rateLimitState{
			limit:             limiter.options.maximum,
			remaining:         0,
			resetAt:           counter.resetAt,
			retryAfterSeconds: retryAfterSeconds,
		}, true
	}

	counter.count++
	limiter.counters[key] = counter
	return rateLimitState{
		limit:             limiter.options.maximum,
		remaining:         limiter.options.maximum - counter.count,
		resetAt:           counter.resetAt,
		retryAfterSeconds: retryAfterSeconds,
	}, false
}

func (limiter *fixedWindowLimiter) sweepExpiredCounters(now time.Time) {
	if now.Before(limiter.nextSweepAt) {
		return
	}
	for counterKey, counter := range limiter.counters {
		if !now.Before(counter.resetAt) {
			delete(limiter.counters, counterKey)
		}
	}
	limiter.nextSweepAt = now.Add(limiter.options.window)
}

func (limiter *fixedWindowLimiter) reject(responseWriter http.ResponseWriter, request *http.Request, state rateLimitState) {
	setRateLimitHeaders(responseWriter, state)
	responseWriter.Header().Set("Retry-After", strconv.Itoa(state.retryAfterSeconds))
	if limiter.options.onLimit != nil {
		limiter.options.onLimit(responseWriter, request, state)
		return
	}
	httpx.RespondWithJSON(responseWriter, http.StatusTooManyRequests, map[string]string{"error": "Too many requests"})
}

func fixedWindowRateLimiter(options rateLimitOptions) middleware {
	validateRateLimitOptions(options)
	return func(next http.Handler) http.Handler {
		return next
	}
}

func setRateLimitHeaders(responseWriter http.ResponseWriter, state rateLimitState) {
	responseWriter.Header().Set("RateLimit-Limit", strconv.Itoa(state.limit))
	responseWriter.Header().Set("RateLimit-Remaining", strconv.Itoa(state.remaining))
	responseWriter.Header().Set("RateLimit-Reset", strconv.FormatInt(state.resetAt.Unix()+boolToInt64(state.resetAt.Nanosecond() > 0), 10))
}

func clientIPKey(request *http.Request) string {
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	if request.RemoteAddr != "" {
		return request.RemoteAddr
	}
	return "unknown"
}

func clientIPKeyWithTrustedProxies(trustedProxyHops int) func(*http.Request) string {
	return func(request *http.Request) string {
		if trustedProxyHops > 0 {
			forwardedAddresses := strings.Split(request.Header.Get("X-Forwarded-For"), ",")
			selectedIndex := len(forwardedAddresses) - trustedProxyHops
			if selectedIndex >= 0 && selectedIndex < len(forwardedAddresses) {
				if selectedAddress := strings.TrimSpace(forwardedAddresses[selectedIndex]); selectedAddress != "" {
					return selectedAddress
				}
			}
		}
		return clientIPKey(request)
	}
}

func boolToInt64(value bool) int64 {
	if value {
		return 1
	}
	return 0
}
