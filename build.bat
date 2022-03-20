set CGO_ENABLED=0
set GOOS=windows
set GOARCH=amd64
go build -o ./dist/obpo_server_win64.exe .