package routes

import (
	adminControllers "github.com/codedwells/GoServer/controllers/admin"
	studentControllers "github.com/codedwells/GoServer/controllers/student"
	"github.com/codedwells/GoServer/middleware"
	"github.com/gofiber/fiber/v2"
)

func SetUpRoutes(app *fiber.App) {
	api := app.Group("/api")

	// Version 1
	v1 := api.Group("/v1")

	// Logout routes
	v1.Get("/logout", studentControllers.Logout)

	// Student routes
	student := v1.Group("/student")
	student.Post("/signup", studentControllers.CreateStudent)
	student.Post("/login", studentControllers.LoginStudent)
	student.Get("/refresh", middleware.StudentAuth, studentControllers.RefreshStudentAccess)
	student.Put("/password", middleware.StudentAuth, studentControllers.UpdatePassword)
	student.Delete("/delete", middleware.AdminAuth, studentControllers.DeleteStudent)

	// Admin routes
	admin := v1.Group("/admin")
	admin.Post("/signup", adminControllers.CreateAdmin)
	admin.Post("/login", adminControllers.LoginAdmin)
	admin.Get("/refresh", middleware.AdminAuth, adminControllers.RefreshAdminAccess)
	admin.Get("/all", middleware.AdminAuth, adminControllers.GetAllAdmins)
	admin.Delete("/delete", middleware.AdminAuth, adminControllers.DeleteAdmin)
	admin.Put("/email", middleware.AdminAuth, adminControllers.UpdateEmail)
	admin.Put("/password", middleware.AdminAuth, adminControllers.UpdatePassword)

}
