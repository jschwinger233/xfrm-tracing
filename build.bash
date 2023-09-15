rm -fr build/
mkdir build
CGO_ENABLED=0 go build -o build/
cp Dockerfile build/
docker build -t uumg/xfrm-tracing build/
