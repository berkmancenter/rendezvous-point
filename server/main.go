package main

import (
	"flag"
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	"github.com/berkmancenter/rendezvous-point/router"
)

func main() {
	port := flag.Int("port", 8080, "Port to listen on")
	overrideIP := flag.String("remote-ip-override", "", "Override remote IP for testing")
	flag.Parse()

	e := echo.New()
	e.HideBanner = true
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORS())

	if *overrideIP != "" {
		e.IPExtractor = func(*http.Request) string {
			return *overrideIP
		}
	}

	router.RegisterRoutes(e)

	e.Logger.Fatal(e.Start(fmt.Sprintf(":%d", *port)))
}
