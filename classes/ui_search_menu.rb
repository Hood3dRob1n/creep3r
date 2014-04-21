# Help Menu
def search_menu_help
  puts "Available Options from Search Menu: ".underline.white
  puts "back".light_yellow + "   => ".white + "Return to Main Menu".light_red
  puts "ask".light_yellow + "    => ".white + "Search w/Ask".light_red
  puts "bing".light_yellow + "   => ".white + "Search w/Bing!".light_red
  puts "google".light_yellow + " => ".white + "Search w/Google".light_red
  puts "yahoo".light_yellow + "  => ".white + "Search w/Yahoo!".light_red
  puts "all".light_yellow + "    => ".white + "Search w/All Search Engines".light_red
  puts "list".light_yellow + "   => ".white + "Load Links from File".light_red
  puts
end

# Main Menu for Search
def search_menu
  puts
  prompt = "(dork3r)> "
  while line = Readline.readline("#{prompt}", true)
    cmd = line.chomp
    case cmd
    when /^!(.+)/
      # Execute system commands in terminal
      cmd=$1.strip.chomp
      res = commandz(cmd)
      print_line("\n#{res.join().chomp}")
      search_menu
    when /^c$|^clear$|^cls$/i
      cls
      banner
      search_menu
    when /^h$|^help$|^ls$/i
      puts
      search_menu_help
      search_menu
    when /^exit$|^quit$|^back$/i
      puts
      print_error("Returning to Main Menu....")
      main_menu
    when  /^ip$/i
      ip_info
      search_menu
    when /^ip2host$|^host2ip$/i
      host = Readline.readline("   Target IP or Domain: ", true)
      dnsenum = DNSEnum.new(host.strip.chomp)
      ip, domain, hostname = dnsenum.host_info
      puts
      print_status("IP: #{ip}")
      print_status("Domain: #{domain}") unless domain == ip
      print_status("Hostname: #{hostname}\n\n")
      search_menu
    when /^list$/i
      file = Readline.readline("   Path to Links File: ", true)
      if File.exists?(file.strip.chomp)
        print_status("Performing quick vuln test with user provided links....")
        links=File.open(file.strip.chomp).readlines
        print_status("Loaded #{links.size} links from #{file}....")
        testing_links = link_prep(links)
        print_status("#{testing_links.size} links prepped for testing....")
        send_and_check(testing_links)
      else
        puts
        print_error("Unable to load URL list!")
        print_error("Check path or permissions and try again....\n")
      end
      search_menu
    when /^ask$|^bing$|^yahoo$|^google|^all$/i
      print_status("Need some info for search....")
      squery = Readline.readline("   Enter Search Term: ", true)
      eanswer = Readline.readline("   Enable TLD Expansion Search (Y/N)? ", true)
      if eanswer.strip.chomp.upcase == 'N' or eanswer.strip.chomp.upcase == 'NO'
        tld_expansion = false
      else
        tld_expansion = true
        line = Readline.readline("   Enter CSV list of TLD's to Expand Search:", true)
        if line =~ /.+,.+/
          tld_expansion_array = line.split(',')
        else
          tld_expansion_array = [ 'COM', 'EDU', 'NET', 'ORG' ]
        end
      end
      answer = Readline.readline("   Enable Vuln Checks w/Search (Y/N)? ", true)
      if answer.strip.chomp.upcase == 'N' or answer.strip.chomp.upcase == 'NO'
        dorking=false
      else
        dorking=true
      end
      puts
      links=[]
      search = SearchEngine.new
      case cmd
      when /ask/i
        if tld_expansion
          tld_expansion_array.each do |t|
            count=links.size
            print_status("Searching with Dork against #{t}....")
            dork = squery.strip.chomp + "%20site%3A#{t}"
            links += search.ask_search(dork, false)
            print_status("Found #{links.size - count.to_i} Links....") unless (links.size - count.to_i) == 0
          end
        else
          links += search.ask_search(squery.strip.chomp)
        end
      when /bing/i
        if tld_expansion
          tld_expansion_array.each do |t|
            count=links.size
            print_status("Searching with Dork against #{t}....")
            dork = squery.strip.chomp + "%20site%3A#{t}"
            links += search.bing_search(dork, false)
            print_status("Found #{links.size - count.to_i} Links....") unless (links.size - count.to_i) == 0
          end
        else
          links += search.bing_search(squery.strip.chomp)
        end
      when /google/i
        if tld_expansion
          tld_expansion_array.each do |t|
            count=links.size
            print_status("Searching with Dork against #{t}....")
            dork = squery.strip.chomp + "%20site%3A#{t}"
            links += search.google_search(dork, false)
            print_status("Found #{links.size - count.to_i} Links....") unless (links.size - count.to_i) == 0
          end
        else
          links += search.google_search(squery.strip.chomp)
        end
      when /excite/i
        if tld_expansion
          tld_expansion_array.each do |t|
            count=links.size
            print_status("Searching with Dork against #{t}....")
            dork = squery.strip.chomp + "%20site%3A#{t}"
            links += search.excite_search(dork, false)
            print_status("Found #{links.size - count.to_i} Links....") unless (links.size - count.to_i) == 0
          end
        else
          links += search.excite_search(squery.strip.chomp)
        end
      when /hotbot/i
        if tld_expansion
          tld_expansion_array.each do |t|
            count=links.size
            print_status("Searching with Dork against #{t}....")
            dork = squery.strip.chomp + "%20site%3A#{t}"
            links += search.hotbot_search(dork, false)
            print_status("Found #{links.size - count.to_i} Links....") unless (links.size - count.to_i) == 0
          end
        else
          links += search.hotbot_search(squery.strip.chomp)
        end
      when /yahoo/i
        if tld_expansion
          tld_expansion_array.each do |t|
            count=links.size
            print_status("Searching with Dork against #{t}....")
            dork = squery.strip.chomp + "%20site%3A#{t}"
            links += search.hotbot_search(dork, false)
            print_status("Found #{links.size - count.to_i} Links....") unless (links.size - count.to_i) == 0
          end
        else
          links += search.yahoo_search(squery.strip.chomp)
        end
      else # All
        if tld_expansion
          tld_expansion_array.each do |t|
            count=links.size
            print_status("Searching with Dork against #{t}....")
            dork = squery.strip.chomp + "%20site%3A#{t}"
            links += search.ask_search(dork, false)
            print_status("Ask Found #{links.size - count.to_i} Links....") unless (links.size - count.to_i) == 0
            count=links.size
            links += search.bing_search(dork, false)
            print_status("Bing Found #{links.size - count.to_i} Links....") unless (links.size - count.to_i) == 0
            count=links.size
            links += search.google_search(dork, false)
            print_status("Google Found #{links.size - count.to_i} Links....") unless (links.size - count.to_i) == 0
            count=links.size
            links += search.yahoo_search(dork, false)
            print_status("Yahoo Found #{links.size - count.to_i} Links....") unless (links.size - count.to_i) == 0
          end
        else
          links += search.ask_search(squery.strip.chomp)
          links += search.bing_search(squery.strip.chomp)
          links += search.google_search(squery.strip.chomp)
          links += search.yahoo_search(squery.strip.chomp)
        end
      end
      if not links.nil? and links.size > 0
        links.uniq!
        if dorking
          test_links = link_prep(links)
          print_good("#{test_links.size} links prepped for testing....")
          send_and_check(test_links)
        else
          print_good("Search Results: ")
          links.each {|link| puts link.to_s.white }
        end
        puts
      else
        puts
        print_error("No links returned from searches!")
        print_error("Can't do anything without links....\n\n")
      end
      search_menu
    when /^local$|^OS$/i
      local_shell
      search_menu
    else
      puts
      print_error("Oops, Didn't quite understand that one!")
      print_error("Please try again...\n\n")
      search_menu
    end
  end
end
