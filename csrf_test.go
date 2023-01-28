package csrf_test

import (
	"net/http"
	"os"
	"testing"

	"github.com/gobuffalo/buffalo"
	"github.com/gobuffalo/buffalo/render"
	"github.com/gobuffalo/envy"
	"github.com/gobuffalo/httptest"
	csrf "github.com/gobuffalo/mw-csrf"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	env := envy.Get("GO_ENV", "development")
	envy.Set("GO_ENV", "development")
	defer envy.Set("GO_ENV", env)
	os.Exit(m.Run())
}

type csrfForm struct {
	AuthenticityToken string `form:"authenticity_token"`
}

func ctCSRFApp() *buffalo.App {
	h := func(c buffalo.Context) error {
		if at := c.Value("authenticity_token"); at != nil {
			return c.Render(200, render.String(at.(string)))
		}
		return c.Render(420, nil)
	}
	a := buffalo.New(buffalo.Options{})
	a.Use(csrf.New)
	a.GET("/csrf", h)
	a.POST("/csrf", h)
	return a
}

func Test_CSRFOnIdempotentAction(t *testing.T) {
	r := require.New(t)

	w := httptest.New(ctCSRFApp())
	res := w.HTML("/csrf").Get()
	r.Equal(200, res.Code)
}

func Test_CSRFOnJSONRequest(t *testing.T) {
	r := require.New(t)

	w := httptest.New(ctCSRFApp())

	// Test missing token case
	res := w.HTML("/csrf").Post("")
	r.Equal(http.StatusForbidden, res.Code)
	r.Contains(res.Body.String(), "CSRF token not found in request")

	rs := w.JSON("/csrf").Post("")
	r.Equal(http.StatusForbidden, rs.Code)
	r.Contains(res.Body.String(), "CSRF token not found in request")
}

func Test_CSRF_TestMode(t *testing.T) {
	r := require.New(t)

	env := envy.Get("GO_ENV", "development")
	envy.Set("GO_ENV", "test")
	defer envy.Set("GO_ENV", env)

	w := httptest.New(ctCSRFApp())

	// Test missing token case
	res := w.HTML("/csrf").Post("")
	r.Equal(200, res.Code)

	rs := w.JSON("/csrf").Post("")
	r.Equal(200, rs.Code)
}

func Test_CSRFOnEditingAction(t *testing.T) {
	r := require.New(t)

	w := httptest.New(ctCSRFApp())

	// Test missing token case
	res := w.HTML("/csrf").Post("")
	r.Equal(http.StatusForbidden, res.Code)
	r.Contains(res.Body.String(), "CSRF token not found in request")

	// Test provided bad token through Header case
	req := w.HTML("/csrf")
	req.Headers["X-CSRF-Token"] = "test-token"
	res = req.Post("")
	r.Equal(http.StatusForbidden, res.Code)
	r.Contains(res.Body.String(), "CSRF token not found in request")

	// Test provided good token through Header case
	res = w.HTML("/csrf").Get()
	r.Equal(200, res.Code)
	token := res.Body.String()

	req = w.HTML("/csrf")
	req.Headers["X-CSRF-Token"] = token
	res = req.Post("")
	r.Equal(200, res.Code)

	// Test provided good token through form case
	res = w.HTML("/csrf").Get()
	r.Equal(200, res.Code)
	token = res.Body.String()

	req = w.HTML("/csrf")
	res = req.Post(csrfForm{AuthenticityToken: token})
	r.Equal(200, res.Code)
}
