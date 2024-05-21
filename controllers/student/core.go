package studentControllers

import (
	"net/http"
	"os"
	"time"

	"github.com/codedwells/GoServer/utils"
	"github.com/gofiber/fiber/v2"
)

// Logout User
// @route GET /api/v1/logout/?user=student
func Logout(c *fiber.Ctx) error {
	user := c.Query("user")

	// Create cookie
	cookie := new(fiber.Cookie)

	if user == "user" {

		// Logut student
		cookie.Name = "palace_usr"
		cookie.Value = ""
		cookie.HTTPOnly = utils.Check(os.Getenv("APP_ENV") == "prod", true, false)
		cookie.SameSite = utils.Check(os.Getenv("APP_ENV") == "prod", "strict", "None")
		cookie.Secure = utils.Check(os.Getenv("APP_ENV") == "prod", true, false)
		cookie.Expires = time.Now().Add(-time.Hour)

		// Set cookie
		c.Cookie(cookie)

		return c.Status(http.StatusOK).JSON(&fiber.Map{
			"status":  "success",
			"message": "Logout successful",
		})

	} else {

		// Logout Admin
		cookie.Name = "palace_adm"
		cookie.Value = ""
		cookie.HTTPOnly = utils.Check(os.Getenv("APP_ENV") == "prod", true, false)
		cookie.SameSite = utils.Check(os.Getenv("APP_ENV") == "prod", "strict", "None")
		cookie.Secure = utils.Check(os.Getenv("APP_ENV") == "prod", true, false)
		cookie.Expires = time.Now().Add(-time.Hour)

		// Set cookie
		c.Cookie(cookie)

		return c.Status(http.StatusOK).JSON(&fiber.Map{
			"status":  "success",
			"message": "Logout successful",
		})

	}

}
