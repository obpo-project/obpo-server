package main

import (
	"encoding/json"
	"github.com/gin-gonic/gin"
	"io/ioutil"
	"net/http"
)

type ResultData struct {
	Mba string `json:"mba"`
}

type Response struct {
	Code  int        `json:"code"`
	Error string     `json:"error"`
	Warn  string     `json:"warn"`
	Data  ResultData `json:"data"`
}

func setupRouter() *gin.Engine {
	r := gin.Default()

	r.POST("/request", func(c *gin.Context) {
		request, _ := ioutil.ReadAll(c.Request.Body)
		response, err := json.Marshal(process(string(request)))
		if err != nil {
			c.String(http.StatusBadGateway, `{"code": 502}`)
		} else {
			c.String(http.StatusOK, string(response))
		}
	})
	return r
}

func main() {
	r := setupRouter()
	_ = r.Run(":10000")
}
