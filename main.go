package main

import (
	"io/ioutil"
	"net/http"

	"github.com/gin-gonic/gin"
)

func setupRouter() *gin.Engine {
	r := gin.Default()

	r.POST("/request", func(c *gin.Context) {
		content, _ := ioutil.ReadAll(c.Request.Body)
		c.String(http.StatusOK, RunOBPO(string(content)))
	})
	return r
}

func main() {
	r := setupRouter()
	r.Run(":10000")
}
