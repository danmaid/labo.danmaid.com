package endpoints

import (
	"net/http"
	"net/url"
)

type HTTPControlEndpoint interface {
	ServeHTTP(w http.ResponseWriter, r *http.Request)
}
type Getter interface {
	Get(params HTTPParams, ctx HTTPContext) (any, error)
}

type Poster interface {
	Post(payload HTTPPayload, params HTTPParams, ctx HTTPContext) (any, error)
}

type Putter interface {
	Put(payload HTTPPayload, params HTTPParams, ctx HTTPContext) (any, error)
}

type Deleter interface {
	Delete(params HTTPParams, ctx HTTPContext) (any, error)
}
type HTTPContext struct {
	Request  *http.Request
	Response http.ResponseWriter
}
type HTTPPayload interface {
	Json() (any, error)
}
type HTTPParams = url.Values
