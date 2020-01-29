FROM golang:latest
WORKDIR /go/src
COPY . .
RUN go build web_chain.go
EXPOSE 8080
CMD ["./web_chain"]


