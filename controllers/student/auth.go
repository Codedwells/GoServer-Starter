package studentControllers

import (
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/codedwells/GoServer/database"
	"github.com/codedwells/GoServer/models"
	"github.com/codedwells/GoServer/utils"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// Student Related Controllers

// Create Student
// @route POST /api/v1/student/signup
func CreateStudent(c *fiber.Ctx) error {
	body := new(models.StudentSignUp)

	if err := c.BodyParser(body); err != nil {
		return c.Status(400).JSON(err.Error())
	}

	// Hash password
	hashedPassword, hashingError := utils.CreateHashFromText(body.Password, 10)

	if hashingError != nil {
		return c.Status(http.StatusInternalServerError).JSON(&fiber.Map{
			"status":  "error",
			"message": "An error occurred while creating account",
		})
	}

	// Create user
	user := models.Student{
		ID:       uuid.New(),
		Name:     body.Name,
		Email:    body.Email,
		Password: hashedPassword,
	}

	// Add user to database
	result := database.DB.Db.Create(&user)

	if result.Error != nil {
		if strings.Contains(result.Error.Error(), "duplicate key value") {
			return c.Status(http.StatusBadRequest).JSON(&fiber.Map{
				"status":  "error",
				"message": "User already exists",
			})
		}

		return c.Status(http.StatusInternalServerError).JSON("An error occurred while creating account")
	}

	// Generate JWT token
	token, err := utils.SignJwtToken(user.ID.String())

	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(&fiber.Map{
			"status":  "error",
			"message": "An error occurred while creating account",
		})

	}

	// Create cookie
	cookie := new(fiber.Cookie)
	cookie.Name = "edu_usr"
	cookie.Value = token
	cookie.HTTPOnly = utils.Check(os.Getenv("APP_ENV") == "prod", true, false)
	cookie.SameSite = utils.Check(os.Getenv("APP_ENV") == "prod", "strict", "None")
	cookie.Secure = utils.Check(os.Getenv("APP_ENV") == "prod", true, false)
	cookie.Expires = time.Now().Add(24 * time.Hour * 7)

	// Set cookie
	c.Cookie(cookie)

	// Return user data to client
	return c.Status(http.StatusOK).JSON(&fiber.Map{
		"status":  "success",
		"message": "Account created successfully",
		"data": map[string]interface{}{
			"name":             user.Name,
			"email":            user.Email,
			"completed_orders": user.CompletedOrders,
			"placed_orders":    user.PlacedOrders,
			"balance":          user.Balance,
            "active_spend":     user.ActiveSpend,
			"total_spent":      user.TotalSpent,
		},
	})
}

// Login Student
// @route POST /api/v1/student/login
func LoginStudent(c *fiber.Ctx) error {
	body := new(models.SignInInput)

	if err := c.BodyParser(body); err != nil {
		return c.Status(http.StatusBadRequest).JSON(&fiber.Map{
			"status":  "error",
			"message": "Invalid request",
		})
	}

	var user models.Student
	result := database.DB.Db.First(&user, "email = ?", body.Email)

	if result.Error != nil {
		return c.Status(http.StatusNotFound).JSON(&fiber.Map{
			"status":  "error",
			"message": "User not found! Please sign up",
		})
	}

	// Compare password
	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password))

	if err != nil {
		return c.Status(http.StatusUnauthorized).JSON(&fiber.Map{
			"status":  "error",
			"message": "Invalid email or password",
		})
	}

	// Generate JWT token
	token, err := utils.SignJwtToken(user.ID.String())

	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(&fiber.Map{
			"status":  "error",
			"message": "An error occurred while logging you in!",
		})

	}

	// Create cookie
	cookie := new(fiber.Cookie)
	cookie.Name = "edu_usr"
	cookie.Value = token
	cookie.HTTPOnly = utils.Check(os.Getenv("APP_ENV") == "prod", true, false)
	cookie.SameSite = utils.Check(os.Getenv("APP_ENV") == "prod", "strict", "None")
	cookie.Secure = utils.Check(os.Getenv("APP_ENV") == "prod", true, false)
	cookie.Expires = time.Now().Add(24 * time.Hour * 7)

	// Set cookie
	c.Cookie(cookie)

	// Return user data to client
	return c.Status(http.StatusOK).JSON(&fiber.Map{
		"status":  "success",
		"message": "Account created successfully",
		"data": map[string]interface{}{
			"name":             user.Name,
			"email":            user.Email,
			"completed_orders": user.CompletedOrders,
			"placed_orders":    user.PlacedOrders,
			"balance":          user.Balance,
            "active_spend":     user.ActiveSpend,
			"total_spent":      user.TotalSpent,
		},
	})

}

// Update Password
// @route PUT /api/v1/student/password
func UpdatePassword(c *fiber.Ctx) error {
	UserId := c.Locals("userId")

	type ReqBody struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}

	body := new(ReqBody)

	if err := c.BodyParser(body); err != nil {
		return c.Status(http.StatusBadRequest).JSON(&fiber.Map{
			"status":  "error",
			"message": "Invalid request",
		})
	}

	// Find user
	var user models.Student
	result := database.DB.Db.First(&user, "id = ?", UserId)

	if result.Error != nil {
		return c.Status(http.StatusNotFound).JSON(&fiber.Map{
			"status":  "error",
			"message": "Student not found",
		})
	}

	// Compare password
	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.OldPassword))

	if err != nil {
		return c.Status(http.StatusUnauthorized).JSON(&fiber.Map{
			"status":  "error",
			"message": "Unauthorized please login to perfom this action!",
		})
	}

	// Hash new password
	hashedPassword, hashingError := utils.CreateHashFromText(body.NewPassword, 10)

	if hashingError != nil {
		return c.Status(http.StatusInternalServerError).JSON(&fiber.Map{
			"status":  "error",
			"message": "An error occurred while updating password",
		})
	}

	// Update password
	database.DB.Db.Model(&user).Update("password", hashedPassword)

	// Return success message
	return c.Status(http.StatusOK).JSON(&fiber.Map{
		"status":  "success",
		"message": "Password updated successfully",
	})
}

// Delete Student
// @route DELETE /api/v1/student/delete
func DeleteStudent(c *fiber.Ctx) error {
	type ReqBody struct {
		UserId string `json:"user_id"`
	}

	body := new(ReqBody)

	if err := c.BodyParser(body); err != nil {
		return c.Status(http.StatusBadRequest).JSON(&fiber.Map{
			"status":  "error",
			"message": "Invalid request",
		})
	}

	// Find user
	var user models.Student
	result := database.DB.Db.First(&user, "id = ?", body.UserId)

	if result.Error != nil {
		return c.Status(http.StatusNotFound).JSON(&fiber.Map{
			"status":  "error",
			"message": "Student not found",
		})
	}

	// Delete user
	database.DB.Db.Unscoped().Delete(&user)

	// Return success message
	return c.Status(http.StatusOK).JSON(&fiber.Map{
		"status":  "success",
		"message": "Student deleted successfully",
	})
}

// Refresh Student Access
// @route GET /api/v1/student/refresh
func RefreshStudentAccess(c *fiber.Ctx) error {
	UserId := c.Locals("userId")

	var user models.Student
	result := database.DB.Db.First(&user, "id = ?", UserId)

	if result.Error != nil {
		return c.Status(http.StatusNotFound).JSON(&fiber.Map{
			"status":  "error",
			"message": "We could not refresh your access, please login again!",
		})
	}

	// Return user data to client
	return c.Status(http.StatusOK).JSON(&fiber.Map{
		"status": "success",
		"data": map[string]interface{}{
			"name":             user.Name,
			"email":            user.Email,
			"completed_orders": user.CompletedOrders,
			"placed_orders":    user.PlacedOrders,
			"balance":          user.Balance,
            "active_spend":     user.ActiveSpend,
			"total_spent":      user.TotalSpent,
		},
	})
}
