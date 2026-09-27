FROM golang:1.26.6 AS build
WORKDIR /src
COPY main.go .
RUN go mod init mock && CGO_ENABLED=0 go build -o /mock .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /mock /mock
EXPOSE 8080
ENTRYPOINT ["/mock"]
