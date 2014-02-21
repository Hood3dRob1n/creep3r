# Wordlist Mangler Tool
# Perform various transformations on existing wordlists to build new ones
# Quick Configuration Wizard on intializing, then mangle things when ready
# Use hashcat utilities if you need to perform extensive or specific manipulations
# This is more of a fun and learning and for an 80/20 rule...
class WordlistMangler
  def initialize(base_wordlist, combo_list=nil)
    @base_wordlist = base_wordlist
    @mangle_opts = {
      'MIN' => 1,
      'MAX' => 16,
      'UPCASE' => true,
      'DOWNCASE' => true,
      'CAPITALIZE' => true,
      'REVERSE' => true,
      'SWAPCASE' => true,
      'DOUBLE' => true,
      'LEET' => true,
      'PUNCTUATION' => true,
      'DIGITS' => true,
      'YEARS' => { 'ACTIVE' => true, 'START' => 1900, 'STOP' => 2050 },
      'ED' => true,
      'ING' => true,
    }
    @mangle_opts['COMBO']['ACTIVE'] = true unless combo_list.nil?
    @mangle_opts['COMBO']['WORDLIST'] = combo_list unless combo_list.nil?
  end

  # Wizard Menu to Disable any settings before mangling
  def config_update
    minimum = Readline.readline("   Minimum Length: ", true)
    @mangle_opts['MIN'] = minimum.strip.chomp.to_i
    maximum = Readline.readline("   Maximum Length: ", true)
    @mangle_opts['MAX'] = maximum.strip.chomp.to_i
    upcase_opt = Readline.readline("   Enable Uppercase (Y/N): ", true)
    @mangle_opts['UPCASE'] = false if upcase_opt[0].upcase == 'N'
    downcase_opt = Readline.readline("   Enable Lowercase (Y/N): ", true)
    @mangle_opts['DOWNCASE'] = false if downcase_opt[0].upcase == 'N'
    cap_opt = Readline.readline("   Enable Capitalization (Y/N): ", true)
    @mangle_opts['CAPITALIZE'] = false if cap_opt[0].upcase == 'N'
    reverse_opt = Readline.readline("   Enable Reverse (Y/N): ", true)
    @mangle_opts['REVERSE'] = false if reverse_opt[0].upcase == 'N'
    swap_opt = Readline.readline("   Enable Swap Case (Y/N): ", true)
    @mangle_opts['SWAPCASE'] = false if swap_opt[0].upcase == 'N'
    double_opt = Readline.readline("   Enable Double Word (Y/N): ", true)
    @mangle_opts['DOUBLE'] = false if double_opt[0].upcase == 'N'
    l337_opt = Readline.readline("   Enable 1337 Conversion (Y/N): ", true)
    @mangle_opts['LEET'] = false if l337_opt[0].upcase == 'N'
    punc_opt = Readline.readline("   Enable Puncuation (Y/N): ", true)
    @mangle_opts['PUNCTUATION'] = false if punc_opt[0].upcase == 'N'
    nums_opt = Readline.readline("   Enable Numbers (Y/N): ", true)
    @mangle_opts['DIGITS'] = false if nums_opt[0].upcase == 'N'
    years_opt = Readline.readline("   Enable Years (Y/N): ", true)
    if years_opt[0].upcase == 'N'
      @mangle_opts['YEARS']['ACTIVE'] = false
    else
      start_yr = Readline.readline("   Start Year (i.e. 1900): ", true)
      @mangle_opts['YEARS']['START'] = start_yr.strip.chomp.to_i
      stop_yr = Readline.readline("   Stop Year (i.e. 2020): ", true)
      @mangle_opts['YEARS']['STOP'] = stop_yr.strip.chomp.to_i
    end
    ed_opt = Readline.readline("   Enable 'ed' Appending (Y/N): ", true)
    @mangle_opts['ED'] = false if ed_opt[0].upcase == 'N'
    ing_opt = Readline.readline("   Enable 'ing' Appending (Y/N): ", true)
    @mangle_opts['ING'] = false if ing_opt[0].upcase == 'N'
    puts
    print_good("OK, Mangler is Fully Configured Now!\n")
  end

  # Now we mangle base wordlist
  # Creating new wordlist when done
  # Saved in ./results/wordlists/
  def mangle
    count=0
    new_words = []
    out = RESULTS + 'wordlists/'
    Dir.mkdir(out) unless File.exists?(out) and File.directory?(out)
    new_file = out + 'new_wordlist.lst'
    f = File.open(new_file, 'w+')
    if not @mangle_opts['COMBO']['ACTIVE']
      # Standard Mode, Only a single Wordlists....
      print_status("Starting the mangler against #{@base_wordlist}....")
      old_file = File.open(@base_wordlist)
      old_file.each do |w|
        word = w.strip.chomp
        new_words << word # Base word
        new_words << word.upcase if @mangle_opts['UPCASE']         # UPPER
        new_words << word.downcase if @mangle_opts['DOWNCASE']     # lower
        new_words << word.capitalize if @mangle_opts['CAPITALIZE'] # Capitalized
        new_words << word.reverse if @mangle_opts['REVERSE']       # esrever
        new_words << word.swapcase if @mangle_opts['SWAPCASE']     # SwapCase to sWAPcASE
        new_words << word + word if @mangle_opts['DOUBLE']         # wordword
        new_words << word + 'ed' if @mangle_opts['ED']             # bust to busted
        new_words << word + 'ing' if @mangle_opts['ING']           # bust to busting

        # Dump shit to file as we go to avoid nuking memory as best we can
        if new_words.size >= 10000
          new_words.uniq.each { |x| f.puts x.chomp }
          new_words=[]
        end

        # Add Special Chars & Punctuation Before & After our base word
        if @mangle_opts['PUNCTUATION']
          punctuation = [ '!', '@', '$', '^', '&', '*', '(', ')', ',', '.', ';', ':', '?', '<3' ] 
          punctuation.each do |x|
            new_words << x + word
            new_words << word + x
          end
        end

        # Dump if needed...
        if new_words.size >= 10000
          new_words.uniq.each { |x| f.puts x.chomp }
          new_words=[]
        end

        # Add digits Before and After base word
        # word to word1, 1word, word12, 12word, word123, 123word
        if @mangle_opts['DIGITS']
          (0..999).each do |x|
            new_words << x.to_s + word
            new_words << word + x.to_s
          end
        end

        # Dump if needed...
        if new_words.size >= 10000
          new_words.uniq.each { |x| f.puts x.chomp }
          new_words=[]
        end

        # Enumerate Range of Years
        # Attach Before & After our base word
        # johndoe to johndoe1999, 1999johndoe, johndoe2000, 2000johndoe, johndoe2001, etc
        if @mangle_opts['YEARS']['ACTIVE']
          (@mangle_opts['YEARS']['START'].to_i..@mangle_opts['YEARS']['STOP'].to_i).each do |x|
            new_words << x.to_s + word
            new_words << word + x.to_s
          end
        end

        # Dump if needed...
        if new_words.size >= 10000
          new_words.uniq.each { |x| f.puts x.chomp }
          new_words=[]
        end

        # Simple 1337 Speak Converter
        # Not going to break my back on this one
        # Just covers the basics one by one, then all together
        if @mangle_opts['LEET']
          new_words << word.gsub(/a/i, '@')
          new_words << word.gsub(/a/i, '4')
          new_words << word.gsub(/b/, '8')
          new_words << word.gsub(/B/i, '13')
          new_words << word.gsub(/e/i, '3')
          new_words << word.gsub(/f/i, 'ph')
          new_words << word.gsub(/g/i, '9')
          new_words << word.gsub(/i/i, '1')
          new_words << word.gsub(/i/i, '!')
          new_words << word.gsub(/l/i, '1')
          new_words << word.gsub(/o/i, '0')
          new_words << word.gsub(/s/i, '$')
          new_words << word.gsub(/s/i, '5')
          new_words << word.gsub(/t/i, '7')
          new_words << word.gsub(/t/i, '+')
          new_words << word.gsub(/z/i, '2')
          new_words << word.gsub(/a/i, '@').gsub(/e/i, '3').gsub(/i/i, '1').gsub(/l/i, '1').gsub(/o/i, '0').gsub(/s/i, '$').gsub(/t/i, '7')
          # Dump if needed...
          if new_words.size >= 10000
            new_words.uniq.each { |x| f.puts x.chomp }
            new_words=[]
          end
        end

        # Dump if needed...
        if new_words.size >= 10000
          new_words.uniq.each { |x| f.puts x.chomp }
          new_words=[]
        end
      end
      old_file.close
      new_words.uniq.each { |x| f.puts x.chomp }
      f.close
      print_status("On the home streach now...")
      new_words=[]

      # Now run prepped list through the l337 converter once more
      if @mangle_opts['LEET']
        print_status("Running final l337 conversions on wordlist....")
        seed = File.open(new_file).readlines.uniq.map {|drow| drow.strip.chomp } # our prepped list
        tmp_file = out + 'tmp_wordlist.lst'
        f = File.open(tmp_file, 'w+')
        seed.each do |drow|
          f.puts drow
          f.puts drow.gsub(/a/i, '@') unless seed.include?(drow.gsub(/a/i, '@'))
          f.puts drow.gsub(/a/i, '4') unless seed.include?(drow.gsub(/a/i, '4'))
          f.puts drow.gsub(/b/, '8') unless seed.include?(drow.gsub(/b/, '8'))
          f.puts drow.gsub(/B/, '13') unless seed.include?(drow.gsub(/B/, '13'))
          f.puts drow.gsub(/e/i, '3') unless seed.include?(drow.gsub(/e/i, '3'))
          f.puts drow.gsub(/f/i, 'ph') unless seed.include?(drow.gsub(/f/i, 'ph'))
          f.puts drow.gsub(/g/i, '9') unless seed.include?(drow.gsub(/g/i, '9'))
          f.puts drow.gsub(/i/i, '1') unless seed.include?(drow.gsub(/i/i, '1'))
          f.puts drow.gsub(/i/i, '!') unless seed.include?(drow.gsub(/i/i, '!'))
          f.puts drow.gsub(/l/i, '1') unless seed.include?(drow.gsub(/l/i, '1'))
          f.puts drow.gsub(/o/i, '0') unless seed.include?(drow.gsub(/o/i, '0'))
          f.puts drow.gsub(/s/i, '$') unless seed.include?(drow.gsub(/s/i, '$'))
          f.puts drow.gsub(/s/i, '5') unless seed.include?(drow.gsub(/s/i, '5'))
          f.puts drow.gsub(/t/i, '7') unless seed.include?(drow.gsub(/t/i, '7'))
          f.puts drow.gsub(/t/i, '+') unless seed.include?(drow.gsub(/t/i, '+'))
          f.puts drow.gsub(/z/i, '2') unless seed.include?(drow.gsub(/z/i, '2'))
          f.puts drow.gsub(/a/i, '@').gsub(/e/i, '3').gsub(/i/i, '1').gsub(/l/i, '1').gsub(/o/i, '0').gsub(/s/i, '$').gsub(/t/i, '7') unless seed.include?(drow.gsub(/a/i, '@').gsub(/e/i, '3').gsub(/i/i, '1').gsub(/l/i, '1').gsub(/o/i, '0').gsub(/s/i, '$').gsub(/t/i, '7'))
        end
        f.close
        seed=[]
        FileUtils.mv(tmp_file, new_file) # Replace with our now updated list
      end

      # Now we trim to size if needed
      mangled_file = out + 'mangled_wordlist.lst'
      f = File.open(mangled_file, 'w+')
      seed = File.open(new_file).readlines.sort.uniq.map {|drow| drow.strip.chomp } # our prepped list
      seed.each do |w|
        f.puts w if w.size >= @mangle_opts['MIN'].to_i and w.size <= @mangle_opts['MAX'].to_i
      end
      FileUtils.rm(new_file) if File.exists?(new_file)
      FileUtils.rm(tmp_file) if File.exists?(tmp_file)
      f.close
      puts

      # Wordlist Mangler Complete!
      print_good("Wordlist Mangler Complete!")
      print_good("Results saved to: #{mangled_file}\n")
    else
      # Combination Mode, Two (2) Wordlists involved....
      print_error("Shit is TBD yo....")
    end
  end
end
