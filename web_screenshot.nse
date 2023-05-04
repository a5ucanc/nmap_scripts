local http = require "http"
local stdnse = require "stdnse"
local shortport = require "shortport"

description = [[
Takes a screenshot of the homepage of an open web server port.
]]

---
-- @output
-- A screenshot of the web server homepage will be saved in the current working directory.
-- The filename will be in the format: <ip>-<port>.png
--
-- @args web_screenshot.url The URL to the web server homepage. (default: /)
--
-- @usage
-- nmap -p 80 --script web_screenshot <target>

author = "OpenAI ChatGPT"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "safe"}

portrule = shortport.http

-- Define the main function
function action(host, port)

  -- Set the default URL to "/"
  local url = stdnse.get_script_args("web_screenshot.url") or "/"

  -- Generate the filename for the screenshot
  local filename = host.ip .. "-" .. port.number .. ".png"

  -- Construct the HTTP request
  local req = http.get(host, port, url)

  -- Check if the request was successful
  if req.status == 200 then

    -- Save the response body to a file
    local file = io.open(filename, "w+")
    file:write(req.body)
    file:close()

    -- Display a message indicating success
    stdnse.print_status("Screenshot saved to " .. filename)

  else

    -- Display a message indicating failure
    stdnse.print_status("Failed to take screenshot of " .. url)

  end

end
