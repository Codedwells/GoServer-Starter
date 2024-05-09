package adminControllers

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

// Admin Related Controllers

// Create Admin
// @route POST /api/v1/admin/signup
func CreateAdmin(c *fiber.Ctx) error {
	body := new(models.AdminSignUp)

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

	// Check for role
	if body.Role != "admin" && body.Role != "super" && body.Role != "support" {
		return c.Status(http.StatusBadRequest).JSON(&fiber.Map{
			"status":  "error",
			"message": "Invalid roles!",
		})
	}

	// Create user
	user := models.Admin{
		ID:       uuid.New(),
		Name:     body.Name,
		Email:    body.Email,
		Role:     body.Role,
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
	cookie.Name = "edu_adm"
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
			"name":  user.Name,
			"email": user.Email,
			"role":  user.Role,
		},
	})
}

// Login Admin
// @route POST /api/v1/admin/login
func LoginAdmin(c *fiber.Ctx) error {
	body := new(models.SignInInput)

	if err := c.BodyParser(body); err != nil {
		return c.Status(http.StatusBadRequest).JSON(&fiber.Map{
			"status":  "error",
			"message": "Invalid request",
		})
	}

	var user models.Admin
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
	cookie.Name = "edu_adm"
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
		"message": "Login successful",
		"data": map[string]interface{}{
			"name":  user.Name,
			"email": user.Email,
			"role":  user.Role,
		},
	})

}

// Get all admins
// @route GET /api/v1/admin/all
func GetAllAdmins(c *fiber.Ctx) error {
	admins := []models.Admin{}
	result := database.DB.Db.Find(&admins)

	if result.Error != nil {
		return c.Status(http.StatusInternalServerError).JSON(&fiber.Map{
			"status":  "error",
			"message": "An error occurred while fetching admins",
		})
	}

	return c.Status(http.StatusOK).JSON(&fiber.Map{
		"status":  "success",
		"message": "Admins fetched successfully",
		"data":    admins,
	})
}

// Delete Admin
// @route DELETE /api/v1/admin/delete
func DeleteAdmin(c *fiber.Ctx) error {
	//Get user Id from Locals
	UserRole := c.Locals("role")

	// Check if admin is super
	if UserRole != "super" {
		return c.Status(http.StatusUnauthorized).JSON(&fiber.Map{
			"status":  "error",
			"message": "Unauthorized action",
		})
	}

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
	var user models.Admin
	result := database.DB.Db.First(&user, "id = ?", body.UserId)

	if result.Error != nil {
		return c.Status(http.StatusNotFound).JSON(&fiber.Map{
			"status":  "error",
			"message": "User not found",
		})
	}

	// Delete user
	database.DB.Db.Unscoped().Delete(&user)

	// Return success message
	return c.Status(http.StatusOK).JSON(&fiber.Map{
		"status":  "success",
		"message": "Admin deleted successfully",
	})
}

// Update Admin Email
// @route PUT /api/v1/admin/email
func UpdateEmail(c *fiber.Ctx) error {
	//Get user Id from Locals
	UserId := c.Locals("userId")

	type ReqBody struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	body := new(ReqBody)

	if err := c.BodyParser(body); err != nil {
		return c.Status(http.StatusBadRequest).JSON(&fiber.Map{
			"status":  "error",
			"message": "Invalid request",
		})
	}

	// Find user
	var user models.Admin
	result := database.DB.Db.First(&user, "id = ?", UserId)

	if result.Error != nil {
		return c.Status(http.StatusNotFound).JSON(&fiber.Map{
			"status":  "error",
			"message": "User not found",
		})
	}

	// Check if password matches
	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password))

	if err != nil {
		return c.Status(http.StatusUnauthorized).JSON(&fiber.Map{
			"status":  "error",
			"message": "Please login to perfom this action!",
		})
	}

	// Update user email
	user.Email = body.Email
	database.DB.Db.Save(&user)

	// Return success message
	return c.Status(http.StatusOK).JSON(&fiber.Map{
		"status":  "success",
		"message": "Email updated successfully",
		"data":    user,
	})
}

// Update Admin Password
// @route PUT /api/v1/admin/password
func UpdatePassword(c *fiber.Ctx) error {
	//Get user Id from Locals
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

	if len(body.NewPassword) < 8 {
		return c.Status(http.StatusBadRequest).JSON(&fiber.Map{
			"status":  "error",
			"message": "Password must be at least 8 characters",
		})

	}

	// Find user
	var user models.Admin
	result := database.DB.Db.First(&user, "id = ?", UserId)

	if result.Error != nil {
		return c.Status(http.StatusNotFound).JSON(&fiber.Map{
			"status":  "error",
			"message": "User not found",
		})
	}

	// Check if password matches
	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.OldPassword))

	if err != nil {
		return c.Status(http.StatusUnauthorized).JSON(&fiber.Map{
			"status":  "error",
			"message": "Please login to perfom this action!",
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

	// Update user password
	user.Password = hashedPassword
	database.DB.Db.Save(&user)

	// Return success message
	return c.Status(http.StatusOK).JSON(&fiber.Map{
		"status":  "success",
		"message": "Password updated successfully",
	})

}

// Refresh Admin Access
// @route POST /api/v1/admin/refresh
func RefreshAdminAccess(c *fiber.Ctx) error {
	//Get user Id from Locals
	UserId := c.Locals("userId")

	// Find user
	var user models.Admin
	result := database.DB.Db.First(&user, "id = ?", UserId)

	if result.Error != nil {
		return c.Status(http.StatusNotFound).JSON(&fiber.Map{
			"status":  "error",
			"message": "We could not refresh your access, please login again!",
		})
	}

	// Return Admin data to client
	return c.Status(http.StatusOK).JSON(&fiber.Map{
		"status":  "success",
		"message": "Login successful",
		"data": map[string]interface{}{
			"name":  user.Name,
			"email": user.Email,
			"role":  user.Role,
		},
	})
}
