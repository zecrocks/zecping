FROM golang:1.20 as builder
WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -v -o zecping .

FROM alpine:latest
WORKDIR /root/

COPY --from=builder /app/zecping /bin/zecping

CMD ["/bin/zecping"]
