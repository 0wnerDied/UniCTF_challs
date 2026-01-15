package main

import (
    "archive/zip"
    "crypto/rand"
    "encoding/hex"
    "fmt"
    "io"
    "net/http"
    "os"
    "os/exec"
    "path/filepath"
    "strings"
    "time"
)

const (
    COOKIE_DIR   = "./cookies"
    WEBAPP_DIR   = "./"
    COOKIE_VALUE = "1145141919810"
    PORT         = ":8888"
)

// generateRandomID generates a random ID using crypto/rand
func generateRandomID() string {
    b := make([]byte, 16)
    rand.Read(b)
    return hex.EncodeToString(b)
}

// PreCheck path validation function - This is the vulnerability point!
// Seems to check cookie file path validity, but actually creates arbitrary files
func PreCheck(path string) error {
    // Create file without writing content - arbitrary file creation vulnerability
    file, err := os.OpenFile(path, os.O_CREATE, 0644)
    if err != nil {
        return err
    }
    file.Close()
    return nil
}

// Validate cookie
func validateCookie(cookieName string) bool {
    // Construct cookie file path - directory traversal vulnerability exists
    cookiePath := filepath.Join(COOKIE_DIR, cookieName)
    
    // "Pre-check" path - vulnerability exploitation point
    if err := PreCheck(cookiePath); err != nil {
        return false
    }
    
    // Read cookie file content for validation
    content, err := os.ReadFile(cookiePath)
    if err != nil {
        return false
    }
    
    return strings.TrimSpace(string(content)) == COOKIE_VALUE
}

// Generate new cookie
func generateCookie(w http.ResponseWriter) string {
    cookieID := generateRandomID()
    cookiePath := filepath.Join(COOKIE_DIR, cookieID)
    
    // Write cookie file
    if err := os.WriteFile(cookiePath, []byte(COOKIE_VALUE), 0644); err != nil {
        return ""
    }
    
    // Set HTTP Cookie
    http.SetCookie(w, &http.Cookie{
        Name:  "session",
        Value: cookieID,
        Path:  "/",
    })
    
    return cookieID
}

// Download webapp files (excluding cookies folder)
func downloadHandler(w http.ResponseWriter, r *http.Request) {
    // Create temporary zip file
    zipPath := "/tmp/webapp_" + time.Now().Format("20060102150405") + ".zip"
    zipFile, err := os.Create(zipPath)
    if err != nil {
        http.Error(w, "Failed to create archive", http.StatusInternalServerError)
        return
    }
    defer os.Remove(zipPath)
    defer zipFile.Close()
    
    zipWriter := zip.NewWriter(zipFile)
    defer zipWriter.Close()
    
    // Traverse webapp directory
    filepath.Walk(WEBAPP_DIR, func(path string, info os.FileInfo, err error) error {
        if err != nil {
            return err
        }
        
        // Skip cookies directory
        if strings.Contains(path, "cookies") {
            return nil
        }
        
        if !info.IsDir() {
            relPath, _ := filepath.Rel(WEBAPP_DIR, path)
            w, _ := zipWriter.Create(relPath)
            file, _ := os.Open(path)
            defer file.Close()
            io.Copy(w, file)
        }
        return nil
    })
    
    zipWriter.Close()
    zipFile.Close()
    
    // Send zip file
    w.Header().Set("Content-Type", "application/zip")
    w.Header().Set("Content-Disposition", "attachment; filename=webapp.zip")
    http.ServeFile(w, r, zipPath)
}

// Check file integrity
func checkHandler(w http.ResponseWriter, r *http.Request) {
    cmd := exec.Command("python3", filepath.Join(WEBAPP_DIR, "check.py"))
    output, err := cmd.CombinedOutput()
    
    if err != nil {
        w.Write([]byte("Integrity check execution failed: " + err.Error() + "\n"))
    }
    
    w.Write([]byte("Integrity Check Results:\n"))
    w.Write([]byte("========================\n\n"))
    w.Write(output)
}

// Homepage handler
func indexHandler(w http.ResponseWriter, r *http.Request) {
    cookie, err := r.Cookie("session")
    
    // If no cookie exists, generate one
    if err != nil || cookie.Value == "" {
        newCookie := generateCookie(w)
        fmt.Fprintf(w, "<h1>Welcome to File Management System</h1>")
        fmt.Fprintf(w, "<p>New session created: %s</p>", newCookie)
        fmt.Fprintf(w, "<p>Please refresh the page to continue</p>")
        return
    }
    
    // Validate cookie
    if !validateCookie(cookie.Value) {
        http.Error(w, "Invalid session", http.StatusForbidden)
        return
    }
    
    // Display functionality page
    html := `
    <!DOCTYPE html>
    <html>
    <head>
        <title>File Management System</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; }
            h1 { color: #333; }
            ul { list-style-type: none; padding: 0; }
            li { margin: 10px 0; }
            a { color: #0066cc; text-decoration: none; padding: 10px; 
                background: #f0f0f0; border-radius: 5px; display: inline-block; }
            a:hover { background: #e0e0e0; }
        </style>
    </head>
    <body>
        <h1>File Management System</h1>
        <h2>Available Functions:</h2>
        <ul>
            <li><a href="/download">📥 Download Files</a> - Download webapp folder contents</li>
            <li><a href="/check">🔍 Integrity Check</a> - Verify folder integrity</li>
        </ul>
    </body>
    </html>
    `
    w.Header().Set("Content-Type", "text/html; charset=utf-8")
    fmt.Fprint(w, html)
}

func main() {
    // Create necessary directories
    os.MkdirAll(COOKIE_DIR, 0755)
    os.MkdirAll(WEBAPP_DIR, 0755)
    
    http.HandleFunc("/", indexHandler)
    http.HandleFunc("/download", downloadHandler)
    http.HandleFunc("/check", checkHandler)
    
    fmt.Println("Server started on port", PORT)
    http.ListenAndServe(PORT, nil)
}