-- Nmap script to open a web page of an open web server port and take a screenshot of the page
-- Usage: nmap -sC -sV -p 80 --script <scriptname> <target>

-- Required NSE libraries
local http = require "http"
local stdnse = require "stdnse"
local shortport = require "shortport"

-- Check if the target port is open and if it's a web server
portrule = shortport.port_or_service({80}, {"http"})
if not portrule then
  stdnse.debug1("Port 80 is not open or not identified as http")
  return
end

-- Define the script arguments
local scripts = {
  homepage = [[
    var page = require('webpage').create();
    page.open('%s', function() {
        page.render('/tmp/screenshot.png');
        phantom.exit();
    });
  ]]
}

-- Define the main function
function main(host, port)
  -- Generate the URL to the web server homepage
  local url = string.format("http://%s:%s/", host.ip, port.number)
  
  -- Display a message
  stdnse.debug1("Opening " .. url)
  
  -- Load the web page and take a screenshot
  local status, result = http.get(url)
  if status == 200 then
    local phantom = stdnse.exec("phantomjs -")
    phantom.stdin:write(string.format(scripts.homepage, url))
    phantom.stdin:close()
    phantom:wait()
    stdnse.debug1("Screenshot saved to /tmp/screenshot.png")
  else
    stdnse.debug1("Failed to open " .. url)
  end
end
