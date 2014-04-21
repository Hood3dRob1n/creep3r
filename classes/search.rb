# This is our Search Engine Class
# If you want to add more search engines add them here
# Should simply perform search and return valid links as an array
# If you add bad links to regex, add to each search engine until i find way to unit in single regex call

class SearchEngine
  def initialize
    @@out = RESULTS + 'search/'
    @http=EasyCurb.new
    Dir.mkdir(@@out) unless File.exists?(@@out) and File.directory?(@@out)

    # Regex Filter gets used to filter out shit sites in results
    # Also good for adding sites you know you dont want to mess with...
    # Add to it as you like....
    @bad_regex = /^$|^\s+$|^\#$|^\#\s+$|google\.com|^\/.+|^javascript|webcache\.googleusercontent\.com|youtube\.com|blogger\.com|excite\.com|infospace\.com|baidu\.com|duckduckgo\.com|google\.com|ask\.com|msn\.com|microsoft\.com|bing\.com|yahoo\.com|live\.com|microsofttranslator\.com|irongeek\.com|tefneth-import\.com|hackforums\.net|freelancer\.com|facebook\.com|mozilla\.org|stackoverflow\.com|php\.net|wikipedia\.org|amazon\.com|4shared\.com|wordpress\.org|about\.com|lycos\.com|lycosasset\.com|zeeblio\.com|weatherzombie\.com|gamesville\.com|soundcloud\.com|phpbuilder\.com|phpnuke\.org|fbi\.gov|nasa\.gov|dhs\.gov|linearcity\.hk|youtube\.com|ptjaviergroup\.com|p4kurd\.com|tizag\.com|discoverbing\.com|devshed\.com|ashiyane\.org|owasp\.org|1923turk\.com|fictionbook\.org|silenthacker\.do\.am|v4-team\.com|codingforums\.com|tudosobrehacker\.com|zymic\.com|forums\.whirlpool\.net\.au|gaza-hacker\.com|immortaltechnique\.co\.uk|w3schools\.com|phpeasystep\.com|mcafee\.com|specialinterestarms\.com|pastesite\.com|pastebin\.com|joomla\.org|joomla\.fr|sourceforge\.net|joesjewelry\.com|twitter\.com|pluslog\.com/
  end

  # Ask.com! Search Function
  # Provide search query and we fetch link results
  # Return the links for first 30 pages as an array
  def ask_search(squery, verbose=true)
    if verbose
      $config['HTTP']['PROGRESS'] = true
    end
    puts "[".light_blue + "*".white + "]".light_blue + " Searching via Ask....".white if verbose
    ask=[]
    goodlinks=[]
    usablelinks=[]
    # Build our array of page requests links
    (0 .. 30).each { |x| ask << "http://www.ask.com/web?q=#{squery}&page=#{x}" }
    # Curl's Multi::Mode for faster requests
    mresponses = @http.multi_get(ask)
    ask.each do |url|
      page = Nokogiri::HTML(mresponses[url].body_str)
      possibles = page.css("a")
      possibles.select do |link|
        begin
	  url = URI.parse(link['href'])
	  if url.scheme == 'http' || url.scheme =='https'
	    usablelinks << link['href']
	  end
	rescue URI::InvalidURIError => err 
	  # If bad link cause error cause its not a link dont freak out, just move on....
	end
      end
    end
    usablelinks = usablelinks.uniq
    usablelinks.each do |url|
      goodlinks << url unless url =~ @bad_regex
    end
    puts "   [".light_green + "+".white + "] ".light_green + "Unique Links: #{goodlinks.length}".white if verbose
    f=File.open("#{@@out}ask.search", 'w+')
    goodlinks.each { |x| f.puts x }
    f.close
    if verbose
      $config['HTTP']['PROGRESS'] = false
    end
    return goodlinks
  end

  # Bing! Search Function
  # Provide search query and we fetch link results
  # Return the links for first 20 pages as an array
  def bing_search(squery, verbose=true)
    if verbose
      $config['HTTP']['PROGRESS'] = true
    end
   puts "[".light_blue + "*".white + "]".light_blue + " Searching via Bing....".white if verbose
    count=9
    secondcount=1
    goodlinks=[]
    usablelinks=[]
    arrayoflinks=[]
    # Loop to grab the required pages we will need from Bing to get all of our results
    while count.to_i <= 225 do
      bing = 'http://www.bing.com/search?q=' + squery.sub(" ", "%20") + '&qs=n&pq=' + squery.sub(" ", "%20") + '&sc=8-5&sp=-1&sk=&first=' + count.to_s + '&FORM=PORE'
      arrayoflinks << bing
      count = count.to_i + 12
    end
    # Curl's Multi::Mode for faster requests
    mresponses = @http.multi_get(arrayoflinks)
    arrayoflinks.each do |url|
      page = Nokogiri::HTML(mresponses[url].body_str)
      possibles = page.css("a")
      possibles.select do |link|
        begin
	  url = URI.parse(link['href'])
	  if url.scheme == 'http' || url.scheme =='https'
	    usablelinks << link['href']
	  end
	rescue URI::InvalidURIError => err 
	  # If bad link cause error cause its not a link dont freak out, just move on....
	end
      end
    end
    usablelinks = usablelinks.uniq
    usablelinks.each do |url|
      goodlinks << url unless url =~ @bad_regex
    end
    puts "   [".light_green + "+".white + "] ".light_green + "Unique Links: #{goodlinks.length}".white if verbose
    f=File.open("#{@@out}bing.search", 'w+')
    goodlinks.each { |x| f.puts x }
    f.close
    if verbose
      $config['HTTP']['PROGRESS'] = false
    end
    return goodlinks
  end

  # Google Search Function
  # We use headless browser to get results
  # Neeeded since they use so much js obfuscation now :(
  # Provide search query and we fetch link results
  # Return the links for first 25 pages as an array of links
  def google_search(squery, verbose=true)
    goodlinks=[]
    usablelinks=[]
    puts "[".light_blue + "*".white + "]".light_blue + " Searching via Google....".white if verbose
    agent = Mechanize.new
    begin
      agent.user_agent = $config['HTTP']['HTTP_USER_AGENT']
      if $config['HTTP']['PROXY']
        if $config['HTTP']['PROXY_AUTH']
          agent.set_proxy($config['HTTP']['PROXY_IP'], $config['HTTP']['PROXY_PORT'].to_i, user=$config['HTTP']['PROXY_USER'], pass=$config['HTTP']['PROXY_PASS'])
        else
          agent.set_proxy($config['HTTP']['PROXY_IP'], $config['HTTP']['PROXY_PORT'].to_i)
        end
      end

      page = agent.get('http://www.google.com/')          # Google main search page
      search_form = page.form(page.forms.first.name)  # Grab the first & only form on page
      search_form.q = squery.gsub(' ', '%20')           # Set our Search Query or Dork value
      # Submit form and create new Page object
      page = agent.submit(search_form, search_form.buttons.first)

      page.links.each do |link|
        # Filter out a bunch of noise & junk links with regex
        usablelinks << link.href unless link.href.nil? or link.href =~ @bad_regex
      end
    rescue OpenSSL::SSL::SSLError,Errno::ETIMEDOUT,Net::HTTP::Persistent::Error,NoMethodError,Zlib::DataError,Mechanize::ResponseCodeError => e
      print_error("Problem Getting Google Results!\n\t=>#{e}\n") if verbose
    end

    # Next we loop through additional pages to get more results
    count=1
    z=['|','\\','/','*','-']
    (1..14).each do |x|
      begin
        page = agent.page.link_with(:text => "Next").click # We need find the "NEXT" link & click it!
        page.links.each do |link|
          print "\r   [".light_blue + "#{z[rand(z.size)]}".white + "] Scraping".light_blue + "...".white
          usablelinks << link.href unless link.href.nil? or link.href =~ @bad_regex
        end
        count += 1
        sleep(1)
      rescue OpenSSL::SSL::SSLError,Errno::ETIMEDOUT,Net::HTTP::Persistent::Error,NoMethodError,Zlib::DataError,Mechanize::ResponseCodeError => e
        print_error("Problem Getting Google Results!\n\t=>#{e}\n") if verbose
      end
    end
    print "\r   [".light_blue + "*".white + "]".light_blue + " Results are in...\n".white
    goodlinks = usablelinks.uniq
    puts "   [".light_green + "+".white + "] ".light_green + "Unique Links: #{goodlinks.length}".white if verbose
    f=File.open("#{@@out}google.search", 'w+')
    goodlinks.each { |x| f.puts x }
    f.close
    return goodlinks
  end

  # Yahoo! Search Engine
  # Provides search query and we fetch link results
  # Return the links for first 15 pages as an array
  def yahoo_search(squery, verbose=true)
    goodlinks=[]
    usablelinks=[]
    puts "[".light_blue + "*".white + "]".light_blue + " Searching via Yahoo....".white if verbose
    agent = Mechanize.new
    begin
      agent.user_agent = $config['HTTP']['HTTP_USER_AGENT']
      if $config['HTTP']['PROXY']
        if $config['HTTP']['PROXY_AUTH']
          agent.set_proxy($config['HTTP']['PROXY_IP'], $config['HTTP']['PROXY_PORT'].to_i, user=$config['HTTP']['PROXY_USER'], pass=$config['HTTP']['PROXY_PASS'])
        else
          agent.set_proxy($config['HTTP']['PROXY_IP'], $config['HTTP']['PROXY_PORT'].to_i)
        end
      end

      page = agent.get('https://search.yahoo.com/')
      search_form = page.form(page.forms.first.name)
      search_form.p = squery.gsub(' ', '%20')
      page = agent.submit(search_form, search_form.buttons.first)
      page.links.each do |link|
        if not link.text =~ /Cached/i
          if not link.href.nil? and link.href =~ /^http:\/\/r\.search\.yahoo\.com\//
            if link.href =~ /\/RU=(.+)\/RK=0/
              url = $1
              usablelinks << CGI::unescape(url) unless CGI::unescape(url) =~ @bad_regex
            end
          end
        end
      end
    rescue OpenSSL::SSL::SSLError,Errno::ETIMEDOUT,Net::HTTP::Persistent::Error,NoMethodError,Zlib::DataError,Mechanize::ResponseCodeError => e
      print_error("Problem Getting Yahoo Results!\n\t=>#{e}\n") if verbose
    end
    count=1
    z=['|','\\','/','*','-']
    (1..9).each do |x|
      begin
        page = agent.page.link_with(:text => "Next").click
        page.links.each do |link|
          print "\r   [".light_blue + "#{z[rand(z.size)]}".white + "] Scraping".light_blue + "...".white
          if not link.text =~ /Cached/i
            if not link.href.nil? and link.href =~ /^http:\/\/r\.search\.yahoo\.com\//
              if link.href =~ /\/RU=(.+)\/RK=0/
                url = $1
                usablelinks << CGI::unescape(url) unless CGI::unescape(url) =~ @bad_regex
              end
            end
          end
        end
        count += 1
        sleep(1)
      rescue OpenSSL::SSL::SSLError,Errno::ETIMEDOUT,Net::HTTP::Persistent::Error,NoMethodError,Zlib::DataError,Mechanize::ResponseCodeError => e
        print_error("Problem Getting Yahoo! Results from page #{count}!\n\t=>#{e}\n") if verbose
      end
    end
    print "\r   [".light_blue + "*".white + "]".light_blue + " Results are in...\n".white
    goodlinks = usablelinks.uniq
    puts "   [".light_green + "+".white + "] ".light_green + "Unique Links: #{goodlinks.length}".white if verbose
    f=File.open("#{@@out}yahoo.search", 'w+')
    goodlinks.each { |x| f.puts x }
    f.close
    return goodlinks
  end

  # Run Search against ShellStorm API & Display Results in Table
  # Search is run in against all lowercase on server side
  # Need to .downcase our search before sending or results fail!
  # Many Thanks to Jonathan Salwan for his hard work and great site!
  def shellstorm_search(squery, verbose=true)
    url = "http://shell-storm.org/api/?s=#{squery.downcase.urienc}"
    res = @http.get(url)
    if res[1] == 200
      t=[ [ "Author", 'Platform', 'Description', 'ID' ] ]
      res[0].split("\n").each do |entry|
        show = entry.split("::::")
        t << [ "#{show[0]}", "#{show[1]}", "#{show[2]}", "#{show[3]}" ]
      end
      table = t.to_table(:first_row_is_head => true)
      puts table.to_s.white if verbose
      return table
    else
      puts if verbose
      print_error("Problem running ShellStorm Search!") if verbose
      print_caution("Received: #{res[1]}?") if verbose
      print_error("Sorry, Try again in a bit....\n") if verbose
      return nil
    end
  end

  # Seaarch & Display ShellStorm Shellcode by its ID
  # *ID Found using shellstorm_search(squery)
  def shellstorm_shellcode_search(id, verbose=true)
    url = "http://shell-storm.org/shellcode/files/shellcode-#{id.urienc}.php"
    res = @http.get(url)
    if res[1] == 200
      shellcode = res[0].split("\n")[7..-13].join("\n").gsub('&quot;', '"').gsub('&gt;', '>').gsub('&lt;', '<').gsub('&amp;', '&')
      print_line(shellcode) if verbose
      return shellcode
    else
      puts if verbose
      print_error("Problem running ShellStorm Shellcode Search!") if verbose
      print_caution("Received: #{res[1]}?") if verbose
      print_error("Sorry, Try again in a bit....\n") if verbose
      return nil
    end
  end
end
