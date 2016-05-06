package middleware

import (
	"log"
	"net/http"

	"github.com/opentracing/opentracing-go"
	"golang.org/x/net/context"
)

type TracerMiddleware struct{}

func (tm TracerMiddleware) WrapHandler(handler func(ctx context.Context, w http.ResponseWriter, r *http.Request, vars map[string]string) error) func(ctx context.Context, w http.ResponseWriter, r *http.Request, vars map[string]string) error {
	return func(ctx context.Context, w http.ResponseWriter, r *http.Request, vars map[string]string) error {
		carrier := opentracing.HTTPHeaderTextMapCarrier(r.Header)
		span, err := opentracing.GlobalTracer().Join(r.URL.Path, opentracing.TextMap, carrier)
		if err != nil {
			log.Println(err)
		}
		if span != nil {
			defer span.Finish()
			ctx = opentracing.ContextWithSpan(ctx, span)
		}
		return handler(ctx, w, r, vars)
	}
}
