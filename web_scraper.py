#!/usr/bin/env python3
"""
Enhanced VitalSource Web Scraper
Fixed Selenium deprecation issues and improved reliability
For educational purposes only - Use only on content you own or have permission to scrape
"""

import sys
import time
import os
import re
import json
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import TimeoutException, NoSuchElementException, NoSuchFrameException

class EnhancedScraper:
    def __init__(self, webpage, username, password, download_path=None):
        self.webpage = webpage
        self.username = username
        self.password = password
        
        # Set up Chrome options
        chrome_options = Options()
        
        # PDF printing settings
        settings = {
            "recentDestinations": [{
                "id": "Save as PDF",
                "origin": "local",
                "account": "",
            }],
            "selectedDestinationId": "Save as PDF",
            "version": 2,
            "isHeaderFooterEnabled": False,
            "isCssBackgroundEnabled": True,
            "pageWidth": 8.27,  # A4 width in inches
            "pageHeight": 11.69,  # A4 height in inches
            "marginTop": 0.4,
            "marginBottom": 0.4,
            "marginLeft": 0.4,
            "marginRight": 0.4,
            "scale": 1
        }
        
        prefs = {
            'printing.print_preview_sticky_settings.appState': json.dumps(settings),
            'savefile.default_directory': download_path or os.path.expanduser('~/Downloads'),
            'download.prompt_for_download': False,
            'download.default_directory': download_path or os.path.expanduser('~/Downloads')
        }
        
        chrome_options.add_experimental_option('prefs', prefs)
        chrome_options.add_argument('--kiosk-printing')
        chrome_options.add_argument('--disable-gpu')
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')
        
        # Optional: Run headless (without browser window)
        # chrome_options.add_argument('--headless')
        
        # Initialize driver with error handling
        try:
            self.driver = webdriver.Chrome(options=chrome_options)
            self.driver.set_window_size(1920, 1080)  # Set window size
            self.wait = WebDriverWait(self.driver, 20)  # Wait up to 20 seconds
            print("[+] WebDriver initialized successfully")
        except Exception as e:
            print(f"[-] Failed to initialize WebDriver: {e}")
            print("[!] Make sure you have Chrome and ChromeDriver installed")
            sys.exit(1)
    
    def safe_find_element(self, by, value, timeout=10):
        """Safely find element with timeout"""
        try:
            return WebDriverWait(self.driver, timeout).until(
                EC.presence_of_element_located((by, value))
            )
        except TimeoutException:
            print(f"[-] Timeout waiting for element: {value}")
            return None
    
    def login(self):
        """Handle login to the platform"""
        print("[+] Attempting to login...")
        
        try:
            # Extract login page URL
            login_page = self.webpage.split("/#/")[0]
            if "vitalsource.com" not in login_page:
                login_page = "https://accounts.vitalsource.com/"
            
            print(f"[+] Loading login page: {login_page}")
            self.driver.get(login_page)
            
            # Wait for page to load
            time.sleep(3)
            
            # Try different login field selectors
            email_selectors = [
                (By.ID, "email-field"),
                (By.NAME, "email"),
                (By.CSS_SELECTOR, "input[type='email']"),
                (By.XPATH, "//input[@placeholder='Email']")
            ]
            
            email_field = None
            for selector in email_selectors:
                email_field = self.safe_find_element(*selector)
                if email_field:
                    break
            
            if not email_field:
                print("[-] Could not find email field. Page structure might have changed.")
                # Take screenshot for debugging
                self.driver.save_screenshot('login_page_error.png')
                print("[+] Screenshot saved as 'login_page_error.png'")
                return False
            
            # Enter credentials
            email_field.clear()
            email_field.send_keys(self.username)
            print("[+] Username entered")
            
            # Find password field
            password_selectors = [
                (By.ID, "password-field"),
                (By.NAME, "password"),
                (By.CSS_SELECTOR, "input[type='password']")
            ]
            
            password_field = None
            for selector in password_selectors:
                password_field = self.safe_find_element(*selector)
                if password_field:
                    break
            
            if password_field:
                password_field.clear()
                password_field.send_keys(self.password)
                print("[+] Password entered")
                
                # Try to submit form
                submit_selectors = [
                    (By.CSS_SELECTOR, "button[type='submit']"),
                    (By.XPATH, "//button[contains(text(), 'Sign In')]"),
                    (By.ID, "signin-form")
                ]
                
                for selector in submit_selectors:
                    try:
                        submit_element = self.driver.find_element(*selector)
                        submit_element.click()
                        print("[+] Login form submitted")
                        break
                    except:
                        continue
                
                # If no submit button found, try JavaScript
                try:
                    self.driver.execute_script('document.querySelector("form").submit()')
                    print("[+] Form submitted via JavaScript")
                except:
                    pass
            else:
                print("[-] Could not find password field")
                return False
            
            # Wait for login to complete
            time.sleep(5)
            
            # Check if login was successful
            if "signin" in self.driver.current_url or "login" in self.driver.current_url:
                print("[-] Login failed! Check your credentials.")
                # Check for error messages
                try:
                    error_msg = self.driver.find_element(By.CSS_SELECTOR, ".error, .alert-danger")
                    print(f"[-] Error message: {error_msg.text}")
                except:
                    pass
                return False
            
            print("[+] Login successful!")
            return True
            
        except Exception as e:
            print(f"[-] Login error: {e}")
            return False
    
    def scrape_content(self):
        """Scrape the main content"""
        print("[+] Navigating to target page...")
        
        try:
            self.driver.get(self.webpage)
            time.sleep(8)  # Wait for page to fully load
            
            print("[+] Page loaded. Looking for content...")
            
            # Save initial page source for debugging
            with open('initial_page.html', 'w', encoding='utf-8') as f:
                f.write(self.driver.page_source)
            print("[+] Initial page saved as 'initial_page.html'")
            
            # Try to find iframes
            iframes = self.driver.find_elements(By.TAG_NAME, 'iframe')
            print(f"[+] Found {len(iframes)} iframe(s)")
            
            if len(iframes) >= 2:
                try:
                    # Switch to second iframe (common for book content)
                    self.driver.switch_to.frame(iframes[1])
                    print("[+] Switched to iframe [1]")
                    
                    # Look for epub content
                    try:
                        book_content = self.driver.find_element(By.ID, 'epub-content')
                        self.driver.switch_to.frame(book_content)
                        print("[+] Switched to epub-content iframe")
                    except:
                        print("[-] No epub-content iframe found")
                    
                    # Get the book content
                    book_source = self.driver.page_source
                    print(f"[+] Book source length: {len(book_source)} characters")
                    
                    # Process the content
                    processed_content = self.process_content(book_source)
                    
                    return processed_content
                    
                except Exception as e:
                    print(f"[-] Error switching frames: {e}")
                    # Try alternative approach
                    return self.alternative_scrape()
            else:
                print("[-] Not enough iframes found. Trying alternative approach...")
                return self.alternative_scrape()
                
        except Exception as e:
            print(f"[-] Scraping error: {e}")
            return None
    
    def alternative_scrape(self):
        """Alternative scraping method if iframes don't work"""
        print("[+] Trying alternative scraping method...")
        
        try:
            # Get all page content
            full_source = self.driver.page_source
            
            # Look for book content in divs
            patterns = [
                r'<div[^>]*class="[^"]*epub[^"]*"[^>]*>(.*?)</div>',
                r'<div[^>]*id="[^"]*content[^"]*"[^>]*>(.*?)</div>',
                r'<article[^>]*>(.*?)</article>'
            ]
            
            for pattern in patterns:
                match = re.search(pattern, full_source, re.DOTALL | re.IGNORECASE)
                if match:
                    print(f"[+] Found content with pattern: {pattern[:50]}...")
                    return match.group(1)
            
            print("[-] Could not find book content with patterns")
            return full_source
            
        except Exception as e:
            print(f"[-] Alternative scrape error: {e}")
            return None
    
    def process_content(self, book_source):
        """Process the scraped content"""
        print("[+] Processing content...")
        
        try:
            # Extract book ID from URL
            book_id = None
            url_parts = self.webpage.split('/')
            for part in url_parts:
                if len(part) > 10 and '-' in part:  # Likely a book ID
                    book_id = part
                    break
            
            # Construct base URL for resources
            if book_id:
                base_url = f"https://jigsaw.vitalsource.com/books/{book_id}/epub/OPS"
            else:
                base_url = "https://jigsaw.vitalsource.com/books"
            
            # Clean up the content
            # Remove print styles
            book_source = re.sub(r'<style type="text/css" media="print">.*?</style>', '', book_source, flags=re.DOTALL)
            
            # Fix image paths
            book_source = re.sub(r'src="images/', f'src="{base_url}/images/', book_source)
            
            # Fix CSS paths
            book_source = re.sub(r'href="([^"]+\.css)"', f'href="{base_url}/\\1"', book_source)
            
            # Create HTML wrapper
            html_template = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>Scraped Content - {datetime.now().strftime('%Y-%m-%d')}</title>
                <style>
                    body {{ font-family: Arial, sans-serif; line-height: 1.6; margin: 20px; }}
                    img {{ max-width: 100%; height: auto; }}
                    .page {{ page-break-inside: avoid; margin-bottom: 30px; }}
                </style>
            </head>
            <body>
                <h1>Scraped Content</h1>
                <p>Source: {self.webpage}</p>
                <p>Scraped: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <hr>
                {book_source}
            </body>
            </html>
            """
            
            return html_template
            
        except Exception as e:
            print(f"[-] Content processing error: {e}")
            return book_source  # Return raw source if processing fails
    
    def save_to_pdf(self, content):
        """Save content to PDF"""
        print("[+] Saving to PDF...")
        
        try:
            # Save HTML file
            html_file = os.path.join(os.getcwd(), 'scraped_content.html')
            with open(html_file, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"[+] HTML saved: {html_file}")
            
            # Load in browser for printing
            self.driver.get(f'file://{html_file}')
            time.sleep(3)
            
            # Execute print command
            print("[+] Triggering print dialog...")
            self.driver.execute_script('window.print();')
            
            # Wait for print dialog
            time.sleep(5)
            
            print("[+] PDF should be generated. Check your downloads folder.")
            print("[+] Note: You may need to click 'Save' in the print dialog.")
            
        except Exception as e:
            print(f"[-] PDF saving error: {e}")
            print("[!] Manual step required:")
            print(f"1. Open {html_file} in your browser")
            print("2. Press Ctrl+P (Cmd+P on Mac)")
            print("3. Choose 'Save as PDF'")
            print("4. Click Save")
    
    def run(self):
        """Main execution method"""
        print("\n" + "="*60)
        print("Enhanced VitalSource Web Scraper")
        print("For educational use only - Respect copyright!")
        print("="*60 + "\n")
        
        try:
            # Login
            if not self.login():
                print("[-] Exiting due to login failure")
                self.driver.quit()
                return
            
            # Scrape content
            content = self.scrape_content()
            
            if content:
                # Save to PDF
                self.save_to_pdf(content)
                print("\n[+] Process completed successfully!")
            else:
                print("[-] Failed to scrape content")
            
        except KeyboardInterrupt:
            print("\n[-] Process interrupted by user")
        except Exception as e:
            print(f"[-] Unexpected error: {e}")
            import traceback
            traceback.print_exc()
        finally:
            # Clean up
            print("[+] Cleaning up...")
            time.sleep(2)
            self.driver.quit()
            print("[+] WebDriver closed")

def main():
    import datetime
    
    # Get user input
    print("Enhanced VitalSource Web Scraper")
    print("-" * 40)
    
    webpage = input("Enter the book URL: ").strip()
    if not webpage.startswith('http'):
        webpage = 'https://' + webpage
    
    username = input("Enter your username/email: ").strip()
    password = input("Enter your password: ").strip()
    
    # Optional download path
    download_path = input("Enter download path (press Enter for default Downloads): ").strip()
    if not download_path:
        download_path = None
    
    # Run scraper
    scraper = EnhancedScraper(webpage, username, password, download_path)
    scraper.run()

if __name__ == "__main__":
    main()
