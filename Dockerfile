FROM golang:1.12.1-alpine3.9 as builder

RUN apk update && apk add git

WORKDIR /src

ADD . ./

RUN go build

# final image
FROM alpine:3.9

RUN apk update && apk add ca-certificates --no-cache

RUN mkdir -p /app
RUN mkdir -p /app/key

COPY --from=builder /src/auth-es-proxy /app/auth-es-proxy

EXPOSE 3333
VOLUME ["/app"]
CMD ["/app/auth-es-proxy"]
