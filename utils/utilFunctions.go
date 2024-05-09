package utils

import (
	"errors"
	"fmt"
	"mime/multipart"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

// Generates a unique filename for files
func GenerateUniqueFileName(originalName string) string {
	ext := filepath.Ext(strings.ToLower(originalName))

	newFileName := "pek_images_" + uuid.New().String() + ext
	cleanedName := strings.ReplaceAll(newFileName, "-", "_")

	return cleanedName
}

// Checks if an array contains an element
func ArrayContains(alpha []string, str string) bool {

	// iterate using the for loop
	for i := 0; i < len(alpha); i++ {
		// check
		if alpha[i] == str {
			// return true
			return true
		}
	}
	return false
}

func HandleFileUpload(c *fiber.Ctx) ([]string, error) {
	// Get the file count from the form field
	fileCount, err := strconv.Atoi(c.FormValue("fileCount"))
	if err != nil {
        fmt.Println(err)
		return []string{}, errors.New("Error retrieving file count")
	}

	// Create a slice to store the uploaded files
	files := make([]*multipart.FileHeader, 0, fileCount)

	// Create a slice to store the filenames
	fileNames := make([]string, 0, fileCount)

	// Iterate over the file count and retrieve the files
	for i := 0; i < fileCount; i++ {
        // File names format - file0, file1, file2, ...
		fileHeader, err := c.FormFile("file" + strconv.Itoa(i))
		if err != nil {
            fmt.Println(err)
			return []string{}, errors.New("Error retrieving file")
		}

		files = append(files, fileHeader)
		fileNames = append(fileNames, fileHeader.Filename)
	}

	// Process the uploaded files
	for _, file := range files {
		// Save the file to disk
		err := c.SaveFile(file, fmt.Sprintf("./uploads/%s", file.Filename))
		if err != nil {
            fmt.Println(err)
			return []string{}, errors.New("Error saving file")
		}
	}

	return fileNames, nil
}
