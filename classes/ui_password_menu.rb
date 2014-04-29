# Password Related Tools User Interface Menu
# This is for various password related tools
# crackers, manglers, generators, hashers, identifiers, etc...

# Password Tools Help Menu
def password_usage
  puts "Available Options for Passwords Tools Menu: ".underline.white
  puts "back ".light_yellow + "      => ".white + "Return to Main Menu".light_red
  puts "xorme".light_yellow + "      => ".white + "XOR File Encryptor/Decryptor".light_red
  puts "hasher".light_yellow + "     => ".white + "Password Hashing Tool".light_red
  puts "identify".light_yellow + "   => ".white + "Password Hash Identifier".light_red
  puts "mangler".light_yellow + "    => ".white + "Wordlist Mangler Tool".light_red
  puts "profiler".light_yellow + "   => ".white + "Profile Wordlist Generator".light_red
  puts "findmyhash".light_yellow + " => ".white + "Online Hash Checker/Cracker".light_red
  puts "cracker".light_yellow + "    => ".white + "Simple Wordlist Based Hash Cracker Tool".light_red
  puts "zipy".light_yellow + "       => ".white + "Simple Password Protected Zip Cracker".light_red
  print_line("")
end

# Specialty Tools Menu
def password_menu
  puts
  prompt = "(p@ssw0rds)> "
  while line = Readline.readline("#{prompt}", true)
    cmd = line.chomp
    case cmd
    when /^c$|^clear$|^cls$/i
      cls
      banner
      password_menu
    when /^h$|^help$|^ls$/i
      puts
      password_usage
      password_menu
    when /^exit$|^quit$|^back$/i
      puts
      print_error("Returning to Main Menu....")
      main_menu
    when /^!(.+)/
      cmd=$1.strip.chomp
      res = commandz(cmd)
      print_line("\n#{res.join().chomp}")
      password_menu
    when /^local$|^OS$/i
      local_shell
      password_menu
    when /^config$/i
      print_status("Current Configuration: ")
      pp $config
      password_menu
    when /^ip$/i
      ip_info
      password_menu
    when /^ip2host$|^host2ip$|^resolv/i
      host = Readline.readline("   Target IP or Domain: ", true)
      dnsenum = DNSEnum.new(host.strip.chomp)
      ip, domain, hostname = dnsenum.host_info
      puts
      print_status("IP: #{ip}")
      print_status("Domain: #{domain}") unless domain == ip
      print_status("Hostname: #{hostname}\n\n")
      password_menu
    when /^hasher$|^hashme/i
      str_2hash = Readline.readline("   Enter String to Hash: ", true)
      hasher(str_2hash.strip.chomp)
      password_menu
    when /^identify$|^idenitfyme|^hashid$|^hash.id$/i
      hashed_password = Readline.readline("   Password Hash: ", true)
      puts
      while(true)
        print_caution("Optional Filter to help identify Hash types: ")
        print_caution("0) NO Filter")
        print_caution("1) Unix")
        print_caution("2) Windows")
        print_caution("3) Web or Database Application")
        option = Readline.readline("   Enter Option: ", true)
        puts
        if option.to_s.chomp.to_i >= 0 and option.to_s.chomp.to_i <= 3
          case option.to_s.chomp.to_i
          when 0
            filter=nil
          when 1
            filter='UNIX'
          when 2
            filter='WIN'
          when 3
            filter='WEB'
          end
          break
        else
          puts
          print_error("Invalid Selection!")
          print_error("Please choose a valid option from menu below\n\n")
        end
      end
      identifyme(hashed_password.strip.chomp, filter)
      password_menu
    when /^xorme$|^xor$/i
      input_file = Readline.readline("   Input File: ", true)
      if File.exists?(input_file.strip.chomp)
        output_file = input_file.strip.chomp.split('/')[-1].split('.')[0].to_s + '.xor.output'
        out = RESULTS + 'xor/' + output_file
        Dir.mkdir(RESULTS + 'xor/') unless File.exists?(RESULTS + 'xor/') and File.directory?(RESULTS + 'xor/')
        answer = Readline.readline("   Is this a Binary File (Y/N)? ", true)
        if answer[0].upcase == 'Y'
          binary=true
          data = File.open(input_file.strip.chomp, 'rb').read # Read Binary File
          fh = File.open(out, 'wb') 
        else
          binary=false
          data = File.open(input_file.strip.chomp, 'r').read  # Non-Binary File
          fh = File.open(out, 'w')   
        end
        puts
        while(true)
          print_caution("XOR Key: ")
          print_caution("1) Generate Random Key")
          print_caution("2) User Provided Key\n")
          option = Readline.readline("   Enter Option: ", true)
          puts
          if option.to_s.chomp.to_i == 1 or option.to_s.chomp.to_i == 2
            case option.to_s.chomp.to_i
            when 1
              seed = genkey(16)
              key = "#{seed}" * (data.size / seed.size)
            when 2
              usr_xor_key = Readline.readline("   Enter XOR Key to Use: ", true)
              puts
              if usr_xor_key.strip.chomp.size < data.size
                seed = usr_xor_key.strip.chomp.to_s
                key = "#{seed}" * (data.size / seed.size)
              else
                key = usr_xor_key.strip.chomp.to_s
              end
            end
            fh.write(data.xor(key)) # XOR Data & Write to Output file
            fh.close
            print_status("XOR Complete!")
            print_status("Base File: #{input_file}")
            print_status("Output File: #{out}")
            print_status("Encryption Key Used: #{seed}\n\n")
            break
          else
            puts
            print_error("Invalid Selection!")
            print_error("Please choose a valid option from menu below\n\n")
          end
        end
      else
        puts
        print_error("Unable to load input file!")
        print_error("Check path or permissions and try again....\n")
      end
      password_menu
    when /^crack/i
      while(true)
        print_caution("Select from Supported Hash Types: ")
        print_caution("x) Back to Menu")
        print_caution("1) MD5")
        print_caution("2) SHA1")
        print_caution("3) SHA512")
        print_caution("4) LM")
        print_caution("5) NTLM\n")
        option = Readline.readline("   Enter Option: ", true)
        puts
        if option.to_s.chomp.to_i >= 1 and option.to_s.chomp.to_i <= 5
          case option.to_s.chomp.to_i
          when 1
            hash_type='MD5'
          when 2
            hash_type='SHA1'
          when 3
            hash_type='SHA512'
          when 4
            hash_type='LM'
          when 5
            hash_type='NTLM'
          end
          break
        elsif option.to_s.chomp[0].upcase == 'X'
          puts
          print_error("OK, returning to previous menu...")
          hash_type=nil
          break
        else
          puts
          print_error("Invalid Selection!")
          print_error("Please choose a valid option from menu below\n\n")
        end
      end
      if hash_type.nil?
        password_menu
      end
      while(true)
        print_caution("Hash Input: ")
        print_caution("1) Single Hash")
        print_caution("2) Hash List\n")
        option = Readline.readline("   Enter Option: ", true)
        puts
        if option.to_s.chomp.to_i == 1 or option.to_s.chomp.to_i == 2
          case option.to_s.chomp.to_i
          when 1
            singlehash = Readline.readline("   Provide #{hash_type} Hash: ", true)
            crackme_please = [ singlehash.strip.chomp ]
            puts
            break
          when 2
            filehash = Readline.readline("   Path to #{hash_type} Hash List: ", true)
            if File.exists?(filehash.strip.chomp)
              crackme_please=[]
              prep = File.open(filehash.strip.chomp).readlines
              prep.each { |x| crackme_please << x.strip.chomp }
              puts
              break
            else
              puts
              print_error("Unable to load hash list!")
              print_error("Check path or permissions and try again...\n\n")
            end
          end
          break
        else
          puts
          print_error("Invalid Selection!")
          print_error("Please choose a valid option from menu below\n\n")
        end
      end
      if crackme_please.nil? or crackme_please.empty?
        password_menu
      end
      while(true)
        print_caution("Wordlist Source: ")
        print_caution("1) Single Wordlist")
        print_caution("2) Wordlist Directory\n")
        option = Readline.readline("   Enter Option: ", true)
        puts
        if option.to_s.chomp.to_i == 1 or option.to_s.chomp.to_i == 2
          case option.to_s.chomp.to_i
          when 1
            filewords = Readline.readline("   Wordlist to use: ", true)
            if File.exists?(filewords.strip.chomp)
              wordlists = [ filewords.strip.chomp ]
              break
            else
              puts
              print_error("Unable to load hash list!")
              print_error("Check path or permissions and try again...\n\n")
            end
          when 2
            worddir = Readline.readline("   Directory to find Wordlists: ", true)
            if File.exists?(worddir.strip.chomp) and File.directory?(worddir.strip.chomp)
              wordlists = Dir.glob("#{worddir.strip.chomp}/**")
              break
            else
              puts
              print_error("Unable to load hash list!")
              print_error("Check path or permissions and try again...\n\n")
            end
          end
          break
        else
          puts
          print_error("Invalid Selection!")
          print_error("Please choose a valid option from menu below\n\n")
        end
      end
      simple_crack(hash_type, crackme_please, wordlists)
      password_menu
    when /^findmyhash|^fmh$|^find.+hash/i
      print_status("Online Hash Finder Assistant")
      supported = [ 'MD4', 'MD5', 'LM', 'NTLM', 'LM:NTLM', 'MYSQL', 'SHA1' ]
      while(true)
        print_caution("Supported Hash Types:\n   #{supported.join(',')}\n")
        answer = Readline.readline("   Hash Type to Use: ", true)
        if supported.include?(answer.strip.chomp.upcase)
          htype = answer.strip.chomp.upcase
          break
        else
          puts
          print_error("Unknown Hash Type Provided!")
          print_error("Let's try this one more time, shall we....\n")
        end
      end
      answer = Readline.readline("   Enter Hash: ", true)
      hashstr = answer.strip.chomp
      answer = Readline.readline("   Stop on first success (Y/N)?: ", true)
      puts
      if answer.upcase[0] == 'Y'
        sos=true
      else
        sos=false
      end
      print_status("Running hash search, hang tight...")
      fmh = HashFinder.new(hashstr, sos, htype)
      fmh.total_hash_search()
      password_menu
    when /^zipy$|^zip$|^zip.crack/i
      zip_file = Readline.readline("   Path to Protected Zip: ", true)
      puts
      if File.exists?(zip_file.strip.chomp)
        while(true)
          print_caution("Wordlist Source: ")
          print_caution("1) Single Wordlist")
          print_caution("2) Wordlist Directory\n")
          option = Readline.readline("   Enter Option: ", true)
          puts
          if option.to_s.chomp.to_i == 1 or option.to_s.chomp.to_i == 2
            case option.to_s.chomp.to_i
            when 1
              filewords = Readline.readline("   Wordlist to use: ", true)
              if File.exists?(filewords.strip.chomp)
                wordlists = [ filewords.strip.chomp ]
                break
              else
                puts
                print_error("Unable to load hash list!")
                print_error("Check path or permissions and try again...\n\n")
              end
            when 2
              worddir = Readline.readline("   Directory to find Wordlists: ", true)
              puts
              if File.exists?(worddir.strip.chomp) and File.directory?(worddir.strip.chomp)
                wordlists = Dir.glob("#{worddir.strip.chomp}/**")
                break
              else
                puts
                print_error("Unable to load hash list!")
                print_error("Check path or permissions and try again...\n\n")
              end
            end
            break
          else
            puts
            print_error("Invalid Selection!")
            print_error("Please choose a valid option from menu below\n\n")
          end
        end
        zip_crack(zip_file.strip.chomp, wordlists)
      else
        puts
        print_error("Unable to load Zip file!")
        print_error("Check path or permissions and try again...\n\n")
      end
      password_menu
    when /^mangler$|^wordlist.tool/i
      print_status("Need to gather some info first...\n")
      base_wordlist = Readline.readline("   Base Wordlist to Use: ", true)
      puts
      if File.exists?(base_wordlist.strip.chomp)
        mangler = WordlistMangler.new(base_wordlist.strip.chomp)
        mangler.config_update
        mangler.mangle
      else
        puts
        print_error("Unable to load #{base_wordlist.strip.chomp}!")
        print_error("Check path or permissions and try again...\n\n")
      end
      password_menu
    when /^profile|^wordlist.generator/i
      new_words=[]
      print_status("Profiler questions coming your way....")
      print_status("If providing multiple entries, remember to use CSV format....\n")

      # Known Firstname(s)
      fnames = Readline.readline("   Known Firstname(s): ", true)
      if not fnames.strip.chomp.nil? and fnames.strip.chomp != ''
        fnames.strip.chomp.split(',').each do |x|
          new_words << x unless x.nil? or new_words.include?(x) or x == ''
        end
      end

      # Known Lastname(s)
      lnames = Readline.readline("   Known Lastname(s): ", true)
      if not lnames.strip.chomp.nil? and lnames.strip.chomp != ''
        lnames.strip.chomp.split(',').each do |x|
          new_words << x unless x.nil? or new_words.include?(x) or x == ''
        end
      end

      # Known Birthdate
      bdate = Readline.readline("   Expected Birth Year (i.e. 1969): ", true)
      if not bdate.strip.chomp.nil? and bdate.strip.chomp != ''
        start_date = bdate.strip.chomp.split(',')[0].to_i
        bdate.strip.chomp.split(',').each do |x|
          new_words << x unless x.nil? or new_words.include?(x) or x == ''
        end
      else
        start_date = 1900
      end

      # Known Username(s)
      usernames = Readline.readline("   Known Username/Nickname(s): ", true)
      if not usernames.strip.chomp.nil? and usernames.strip.chomp != ''
        usernames.strip.chomp.split(',').each do |x|
          new_words << x unless x.nil? or new_words.include?(x) or x == ''
        end
      end

      # Known Family Name(s)
      famnames = Readline.readline("   Known Mom/Dad/Sibling Name(s): ", true)
      if not famnames.strip.chomp.nil? and famnames.strip.chomp != ''
        famnames.strip.chomp.split(',').each do |x|
          new_words << x unless x.nil? or new_words.include?(x) or x == ''
        end
      end

      # Known Empoyment Name(s): Company, Boss, idk, interpret as needed :p
      worknames = Readline.readline("   Known Employer(s): ", true)
      if not worknames.strip.chomp.nil? and worknames.strip.chomp != ''
        worknames.strip.chomp.split(',').each do |x|
          new_words << x unless x.nil? or new_words.include?(x) or x == ''
        end
      end

      # Known Girlfriend or Spouse Name(s): first, last, nic, etc
      lovernames = Readline.readline("   Known Significant Other Name(s): ", true)
      if not lovernames.strip.chomp.nil? and lovernames.strip.chomp != ''
        lovernames.strip.chomp.split(',').each do |x|
          new_words << x unless x.nil? or new_words.include?(x) or x == ''
        end
      end

      # Known Pet Name(s)
      petname = Readline.readline("   Known Pet Name(s): ", true)
      if not petname.strip.chomp.nil? and petname.strip.chomp != ''
        petname.strip.chomp.split(',').each do |x|
          new_words << x unless x.nil? or new_words.include?(x) or x == ''
        end
      end

      # Known Favorite Animal(s): cat, dog, duck, horse, unicorn, etc
      animalname = Readline.readline("   Known Favorite Animal(s): ", true)
      if not animalname.strip.chomp.nil? and animalname.strip.chomp != ''
        animalname.strip.chomp.split(',').each do |x|
          new_words << x unless x.nil? or new_words.include?(x) or x == ''
        end
      end
      puts

      # Write our seed list to file
      out = RESULTS + 'wordlists/'
      Dir.mkdir(out) unless File.exists?(out) and File.directory?(out)
      new_file = out + 'profile_wordlist.lst'
      print_status("Writing temporary seed list to file....")
      f = File.new(new_file, 'w+')
      new_words.sort.uniq.each {|x| f.puts x.chomp }
      f.close

      # Now Mangle that shit and build a decent wordlist from seed
      print_status("Running seed list through Mangler, hang tight....")
      mangler = WordlistMangler.new(new_file)
      mangler.mangle
      print_status("Removing temporary seed list file....") if File.exists?(new_file)
      FileUtils.rm(new_file) if File.exists?(new_file)

      password_menu
    else
      puts
      print_error("Oops, Didn't quite understand that one!")
      print_error("Please try again...\n\n")
      password_menu
    end
  end
end
