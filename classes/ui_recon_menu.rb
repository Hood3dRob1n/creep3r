# Help Menu
def recon_menu_help
  puts "Available Options from Recon Menu: ".underline.white
  puts "back".light_yellow + "       => ".white + "Return to Main Menu".light_red
  puts "robots".light_yellow + "     => ".white + "Robots.txt File Reader".light_red
  puts "admin".light_yellow + "      => ".white + "Admin Page Finder".light_red
  puts "buster".light_yellow + "     => ".white + "Directory & File Bruter".light_red
  puts "crawler".light_yellow + "    => ".white + "Site Crawler".light_red
  puts "shodan".light_yellow + "     => ".white + "Shodan Search".light_red
  puts "dnsenum".light_yellow + "    => ".white + "DNS Enumeration".light_red
  puts "subdomains".light_yellow + " => ".white + "DNS Sub-Domain Bruteforcer".light_red
  puts "nmap".light_yellow + "       => ".white + "Simple NMAP Scan".light_red
  puts "service".light_yellow + "    => ".white + "NMAP Service Scan".light_red
  puts "shellstorm".light_yellow + " => ".white + "Shell-Storm Shellcode Search".light_red
  puts
end

# Main Menu for Recon
def recon_menu
  puts
  prompt = "(r3con)> "
  while line = Readline.readline("#{prompt}", true)
    cmd = line.chomp
    case cmd
    when /^!(.+)/
      cmd=$1.strip.chomp
      res = commandz(cmd)
      print_line("\n#{res.join().chomp}")
      recon_menu
    when /^c$|^clear$|^cls$/i
      cls
      banner
      recon_menu
    when /^h$|^help$|^ls$/i
      puts
      recon_menu_help
      recon_menu
    when /^exit$|^quit$|^back$/i
      puts
      print_error("Returning to Main Menu....")
      main_menu
    when /^local$|^OS$/i
      local_shell
      recon_menu
    when  /^ip$/i
      ip_info
      recon_menu
    when /^ip2host$|^host2ip$/i
      host = Readline.readline("   Target IP or Domain: ", true)
      dnsenum = DNSEnum.new(host.strip.chomp)
      ip, domain, hostname = dnsenum.host_info
      puts
      print_status("IP: #{ip}")
      print_status("Domain: #{domain}") unless domain == ip
      print_status("Hostname: #{hostname}\n\n")
      recon_menu
    when /^robot/i
      target = Readline.readline("   Enter Base URL: ", true)
      puts
      crawler = Crawler.new(target.strip.chomp)
      crawler.robots
      recon_menu
    when /^admin$|^finder$/i
      target = Readline.readline("   Enter Base URL: ", true)
      puts "   Language Types: ASP|CFM|JSP|PHP|SHTML|HTML"
      lang = Readline.readline("   Type to Use: ", true)
      if lang.strip.chomp.nil? or lang.strip.chomp == ''
        type = 'php'
      else
        type = lang.strip.chomp.downcase
      end
      puts
      print_status("Running #{type.upcase} Admin Finder...")
      print_status("Target: #{target.strip.chomp}")
      crawler = Crawler.new(target.strip.chomp)
      crawler.admin(type)
      recon_menu
    when /^crawl/i
      target = Readline.readline("   Enter Target URL to Crawl: ", true)
      crawler = Crawler.new(target.strip.chomp, $config['CRAWLER']['LINK_LIMIT'].to_i, $config['CRAWLER']['DEPTH_LIMIT'].to_i, $config['CRAWLER']['THREAD_COUNT'].to_i, $config['CRAWLER']['OBEY_ROBOTS'])
      crawler.crawl_site
      puts
      recon_menu
    when /^dnsenum|^dns.enum/i
      print_status("Need some basic info....")
      target = Readline.readline("   Enter Domain or IP to Enumerate: ", true)
      dnsenum = DNSEnum.new(target.strip.chomp)
      print_status("Running DNS Enumeration and Reverse Lookup....")
      dnsenum.host_recon
      recon_menu
    when /^dnssub|^subdomains|^sub.brute|^subbrute/i
      print_status("Need some basic info....")
      target = Readline.readline("   Enter Domain to Bruteforce Sub-Domains for: ", true)
      dns = DNSEnum.new(target.strip.chomp)
      answer = Readline.readline("   Use default list (Y/N)? ", true)
      if answer[0].upcase == 'N'
        l = Readline.readline("   Enter Path to Sub-Domain Fuzz File: ", true)
        puts
        if File.exists?(l.strip.chomp)
          list = l.strip.chomp
          dns.subdomain_bruter(list)
        else
          print_error("Problem loading sub-domain fuzz file!")
          print_caution("Using default list instead....")
          dns.subdomain_bruter
        end
      else
        puts
        dns.subdomain_bruter
      end
      recon_menu
    when /^nmap/i
      print_status("Need some basic info for scan....")
      target = Readline.readline("   Enter Host or IP to Scan: ", true)
      answer = Readline.readline("   Enable NSE Scripts (Y/N)? ", true)
      puts
      nmap = NMAP.new()
      if answer.strip.chomp.upcase == 'Y' or answer.strip.chomp.upcase == 'YES'
        nmap.scanner(target.strip.chomp)
      else
        nmap.scanner(target.strip.chomp, false)
      end
    when /^buster$/i
      print_status("Directory & File Bruter Setup")
      print_status("Take Base URL and Combine it with paths loaded from file...")
      print_status("Uses HEAD Requests to save time & displays results when finished...")
      puts
      target = Readline.readline("   Enter Base URL: ", true)
      buster_file = Readline.readline("   Path to Buster File: ", true)
      puts
      if File.exists?(buster_file.strip.chomp)
        fuzzies=[]
        File.open(buster_file.strip.chomp).readlines.each do |fuzzy|
          fuzzies << "#{target.strip.chomp}#{fuzzy.chomp}".gsub('//', '/').gsub('http:/', 'http://').gsub('https:/', 'https://')
        end
        multi_head(fuzzies)
      else
        print_error("Unable to load buster file!")
        print_error("Check path or permissions and try again....\n\n")
      end
      recon_menu
    when  /^shodan$/i
      if $config['SHODAN']['APIKEY'].nil? or $config['SHODAN']['APIKEY'] == ''
        puts
        print_error("No Shodan API Key set in config!")
        print_error("Update config file or set with console and try again....\n")
      else
        shodan = ShodanAPI.new($config['SHODAN']['APIKEY'])
        if shodan.connected?
          # Display Basic API Key Info
          shodan.info
          puts
          while(true)
            print_caution("Select Shodan Search Method: ")
            print_caution("1) Shodan Search")
            print_caution("2) Shodan Quick Search")
            print_caution("3) Shodan Exploit Search")
            print_caution("4) Download Exploit by Exploit-ID")
            print_caution("5) Shodan Host Search against IP\n")
            answer = Readline.readline("   Search Method Option: ", true)
            if answer.strip.chomp.to_i >= 1 and answer.strip.chomp.to_i <= 5
              case answer.strip.chomp.to_i
              when 1
                squery = Readline.readline("   Enter Search Query: ", true)
                puts
                results = shodan.search(squery.strip.chomp)
                if not results.nil?
                  Dir.mkdir(RESULTS + 'shodan/') unless File.exists?(RESULTS + 'shodan/') and File.directory?(RESULTS + 'shodan/')
                  print_good("Shodan Search: #{squery.strip.chomp}")
                  f = File.open(RESULTS + 'shodan/shodan_search_results.txt', 'w+')
                  f.puts "Shodan Search: #{squery.strip.chomp}"
                  print_good("Total Results Found: #{results['total']}")
                  f.puts "Total Results Found: #{results['total']}"
                  if not results['countries'].nil? and results['countries'].size > 0
                    results['countries'].each do |country|
                      puts "  [".light_green + "+".white + "]".light_green + " #{country['name']}: #{country['count']}".white
                      f.puts "  #{country['name']}: #{country['count']}"
                    end
                  end
                  puts
                  f.puts
                  results['matches'].each do |host|
                    print_good("Host IP: #{host['ip']}")
                    f.puts "Host IP: #{host['ip']}"
                    print_line("#{host['data']}")
                    f.puts host['data']
                  end
                  f.puts
                  f.close
                else
                  print_error("No Results Found for #{squery.strip.chomp} via Shodan Search!")
                end
                puts
              when 2
                squery = Readline.readline("   Enter Search Query: ", true)
                puts
                ips = shodan.quick_search(squery.strip.chomp)
                if not ips.nil?
                  Dir.mkdir(RESULTS + 'shodan/') unless File.exists?(RESULTS + 'shodan/') and File.directory?(RESULTS + 'shodan/')
                  print_good("Shodan Search: #{squery.strip.chomp}")
                  print_good("Total Results: #{ips.size}")
                  print_good("IP Addresses Returned: ")
                  f = File.open(RESULTS + 'shodan/quick_search-ips.lst', 'w+')
                  ips.each {|x| puts "  #{x}".white; f.puts x }
                  f.close
                else
                  print_error("No Results Found for #{squery.strip.chomp} via Shodan Quick Search!")
                end
                puts
              when 3
                squery = Readline.readline("   Enter Search Query: ", true)
                puts
                print_caution("Select Source for Shodan Exploit Search: ")
                print_caution("1) Exploit-DB")
                print_caution("2) Metasploit\n")
                answer = Readline.readline("   Enter Selection: ", true)
                puts
                if answer.strip.chomp.to_i == 2
                  source = "metasploit"
                else
                  source = "exploitdb"
                end
                results = shodan.sploit_search(squery.strip.chomp, source)
                if not results.nil?
                  Dir.mkdir(RESULTS + 'shodan/') unless File.exists?(RESULTS + 'shodan/') and File.directory?(RESULTS + 'shodan/')
                  f = File.open(RESULTS + "shodan/shodan_#{source}_search_results.txt", 'w+')
                  print_good("Shodan Exploit Search: #{squery.strip.chomp}")
                  f.puts "Shodan Exploit Search: #{squery.strip.chomp}"
                  results.each do |id, stuff|
                    print_good("ID: #{id}") unless id.nil?
                    f.puts "ID: #{id}" unless id.nil?
                    stuff.each do |link, desc|
                      print_good("View: #{link.sub('http://www.metasploit.com/', 'http://www.rapid7.com/db/')}") unless link.nil?
                      f.puts "View: #{link.sub('http://www.metasploit.com/', 'http://www.rapid7.com/db/')}" unless link.nil?
                      if not link.nil? and source.downcase == 'metasploit'
                        print_good("Github Link: https://raw.github.com/rapid7/metasploit-framework/master/#{link.sub('http://www.metasploit.com/', '').sub('/exploit/', '/exploits/').sub(/\/$/, '')}.rb")
                        f.puts "Github Link: https://raw.github.com/rapid7/metasploit-framework/master/#{link.sub('http://www.metasploit.com/', '').sub('/exploit/', '/exploits/').sub(/\/$/, '')}.rb"
                      end
                      print_good("Exploit Description: \n#{desc}") unless desc.nil?
                      f.puts "Exploit Description: \n#{desc}" unless desc.nil?
                      f.puts
                      puts
                    end
                  end
                  f.close
                else
                  print_error("No Results Found for #{squery.strip.chomp} via Shodan Exploit Search!")
                end
                puts
              when 4
                id = Readline.readline("   Exploit-ID to Download: ", true)
                puts
                print_caution("Select Download Source: ")
                print_caution("1) Exploit-DB")
                print_caution("2) Metasploit\n")
                answer = Readline.readline("   Enter Selection: ", true)
                if answer.strip.chomp.to_i == 2
                  source = "metasploit"
                else
                  source = "exploitdb"
                end
                # Now download one of the exploits you found....
                results = shodan.sploit_download(id.strip.chomp, source)
                if not results.nil?
                  downloads = RESULTS + 'shodan/downloads/'
                  Dir.mkdir(RESULTS + 'shodan/') unless File.exists?(RESULTS + 'shodan/') and File.directory?(RESULTS + 'shodan/')
                  Dir.mkdir(downloads) unless File.exists?(downloads) and File.directory?(downloads)
                  f = File.open(downloads + "#{source}-#{id.gsub('/','_')}.code", 'w+')
                  results.each do |k, v|
                    if k == 'Exploit'
                      puts "Saved to".light_green + ": #{downloads}#{source}-#{id}.code".white
                      puts "#{k}".light_green + ": \n#{v}".white
                      f.puts v
                    else
                      puts "#{k}".light_green + ": #{v}".white
                    end
                  end
                  f.close
                else
                  print_error("No Download Results Found for ID#: #{id}")
                end
              when 5
                squery = Readline.readline("   Enter Target Host IP: ", true)
                puts
                results = shodan.host(squery.strip.chomp)
                if not results.nil?
                  Dir.mkdir(RESULTS + 'shodan/') unless File.exists?(RESULTS + 'shodan/') and File.directory?(RESULTS + 'shodan/')
                  f = File.open(RESULTS + 'shodan/' + "shodan_host_search_results.txt", 'w+')
                  print_good("Host IP: #{results['ip']}") unless results['ip'].nil?
                  f.puts "Host IP: #{results['ip']}" unless results['ip'].nil?
                  print_good("ISP: #{results['data'][0]['isp']}") unless results['data'][0]['isp'].nil?
                  f.puts "ISP: #{results['data'][0]['isp']}" unless results['data'][0]['isp'].nil?
                  print_good("Hostname(s): #{results['hostnames'].join(',')}") unless results['hostnames'].empty?
                  f.puts "Hostname(s): #{results['hostnames'].join(',')}" unless results['hostnames'].empty?
                  print_good("Host OS: #{results['os']}") unless results['os'].nil?
                  f.puts "Host OS: #{results['os']}" unless results['os'].nil?
                  print_good("Country: #{results['country_name']}") unless results['country_name'].nil?
                  f.puts "Country: #{results['country_name']}" unless results['country_name'].nil?
                  print_good("City: #{results['city']}") unless results['city'].nil?
                  f.puts "City: #{results['city']}" unless results['city'].nil?
                  print_good("Longitude: #{results['longitude']}") unless results['longitude'].nil? or results['longitude'].nil?
                  f.puts "Longitude: #{results['longitude']}" unless results['longitude'].nil? or results['longitude'].nil?
                  print_good("Latitude: #{results['latitude']}") unless results['longitude'].nil? or results['longitude'].nil?
                  f.puts "Latitude: #{results['latitude']}" unless results['longitude'].nil? or results['longitude'].nil?
                  f.puts
                  puts
                  # We need to split and re-pair up the ports & banners as ports comes after banners in results iteration
                  ban=nil
                  port_banners={}
                  results['data'][0].each do |k, v|
                    if k == 'port'
                      port=v
                      if not ban.nil?
                        port_banners.store(port, ban) # store them in hash so we pair them up properly
                        ban=nil
                      end
                    elsif k == 'banner'
                      ban=v
                    end
                  end
                  # Now we can display them in proper pairs
                  port_banners.each do |port, ban|
                    print_good("Port: #{port}")
                    f.puts "Port: #{port}"
                    print_good("Banner: \n#{ban}")
                    f.puts "Banner: \n#{ban}"
                  end
                  f.puts
                  f.close
                else
                  print_error("No Results Found for host!")
                end
                puts
              end
              break
            else
              puts
              print_error("Invalid option selected!")
              print_error("Please choose a valid option from menu below....\n\n")
            end
          end
        end
      end
      recon_menu
    when  /^shellstorm$|^shellcode$|^shell.storm$|^sstorm$/i
      shell_storm = SearchEngine.new
      while(true)
        print_caution("Select Shell-Storm Search Type: ")
        print_caution("0) Back to Menu")
        print_caution("1) General Search")
        print_caution("2) Display Search w/ID\n")
        answer = Readline.readline("   Enter Option: ", true)
        puts
        if answer.strip.chomp.to_i >= 0 and answer.strip.chomp.to_i <= 2
          case answer.strip.chomp.to_i
          when 0
            print_status("Returning to previous menu...")
            break
          when 1
            squery = Readline.readline("   Enter Search Term: ", true)
            shell_storm.shellstorm_search(squery.strip.chomp)
          when 2
            id = Readline.readline("   Enter ID: ", true)
            shell_storm.shellstorm_shellcode_search(id.strip.chomp)
            puts
          end
        else
          puts
          print_error("Invalid option selected!")
          print_error("Please choose a valid option from menu below....\n\n")
        end
      end
      recon_menu
    when  /^service$|^service.scan|^services$/i
      services = ['FTP','RDP','SMB','SSH','HTTP ','SNMP ','MSSQL','MYSQL','PGSQL','WINRM','TELNET']
      while(true)
        print_caution("Select Service Type: ")
        count=1
        services.each do |srvc|
          print_caution("#{count}) #{srvc} Service Scan")
          count += 1
        end
        puts
        answer = Readline.readline("   Enter Option: ", true)
        puts
        if answer.strip.chomp.to_i >= 1 and answer.strip.chomp.to_i <= 7
          case answer.strip.chomp.to_i
          when 1
            service = 'ftp'
          when 2
            service = 'rdp'
          when 3
            service = 'smb'
          when 4
            service = 'ssh'
          when 5
            service = 'snmp'
          when 6
            service = 'mssql'
          when 7
            service = 'mysql'
          when 8
            service = 'pgsql'
          when 9
            service = 'winrm'
          when 10
            service = 'telnet'
          end
          break
        else
          puts
          print_error("Oops, Didn't quite understand that one!")
          print_error("Please try again using valid option from menu below...\n\n")
        end
      end
      targets = Readline.readline("   Enter Target IP or NMAP Acceptable IP Range: ", true)
      puts
      print_status("Running #{service.upcase} Service Scan against #{targets.strip.chomp}, hang tight....")
      nmap = NMAP.new()
      output = nmap.service_scanner(targets.strip.chomp, service)
      ip = nmap.grep_output_to_hosts(output)
      if ip.nil? or ip.size < 1
        print_error("Sorry, NO Hosts Identified via #{service.upcase} Service Scan!")
      else
        puts
        print_good("Identified #{ip.size} Hosts with #{service.upcase} Service Scan!")
        f = File.open(RESULTS + 'recon/' + "#{service}-hosts.txt", 'a+')
        ip.each do |host_up|
          print_line("   #{host_up}")
          f.puts host_up
        end
        f.close
        if Process.uid == 0
          # Make sure all of our results are readable later on...
          commandz("chmod 777 #{RESULTS}recon/#{targets.strip.chomp}")
          commandz("chmod 777 #{RESULTS}recon/#{targets.strip.chomp}/*")
          commandz("chmod 777 #{RESULTS}recon/#{service}-hosts.txt")
        end
        puts "\n"
        print_good("Hosts saved to #{RESULTS}recon/#{service}-hosts.txt\n")
      end
      recon_menu
    else
      puts
      print_error("Oops, Didn't quite understand that one!")
      print_error("Please try again...\n\n")
      recon_menu
    end
  end
end
