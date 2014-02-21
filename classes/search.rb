# This is our Search Engine Class
# If you want to add more search engines add them here
# Should simply perform search and return valid links as an array
# If you add bad links to regex, add to each search engine until i find way to unit in single regex call

class SearchEngine
  def initialize
    @@out = RESULTS + 'search/'
    @http=EasyCurb.new
    Dir.mkdir(@@out) unless File.exists?(@@out) and File.directory?(@@out)
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
      goodlinks << url unless url =~ /google\.com|ask\.com|msn\.com|microsoft\.com|bing\.com|yahoo\.com|live\.com|microsofttranslator\.com|irongeek\.com|tefneth-import\.com|hackforums\.net|freelancer\.com|facebook\.com|mozilla\.org|stackoverflow\.com|php\.net|wikipedia\.org|amazon\.com|4shared\.com|wordpress\.org|about\.com|phpbuilder\.com|phpnuke\.org|fbi\.gov|nasa\.gov|dhs\.gov|linearcity\.hk|youtube\.com|ptjaviergroup\.com|p4kurd\.com|tizag\.com|discoverbing\.com|devshed\.com|ashiyane\.org|owasp\.org|1923turk\.com|fictionbook\.org|silenthacker\.do\.am|v4-team\.com|codingforums\.com|tudosobrehacker\.com|zymic\.com|forums\.whirlpool\.net\.au|gaza-hacker\.com|immortaltechnique\.co\.uk|w3schools\.com|phpeasystep\.com|mcafee\.com|specialinterestarms\.com|pastesite\.com|pastebin\.com|joomla\.org|joomla\.fr|sourceforge\.net|joesjewelry\.com|twitter\.com/i
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
      goodlinks << url unless url =~ /baidu\.com|msn\.com|microsoft\.com|bing\.com|yahoo\.com|live\.com|microsofttranslator\.com|irongeek\.com|tefneth-import\.com|hackforums\.net|freelancer\.com|facebook\.com|mozilla\.org|stackoverflow\.com|php\.net|wikipedia\.org|amazon\.com|4shared\.com|wordpress\.org|about\.com|phpbuilder\.com|phpnuke\.org|fbi\.gov|nasa\.gov|dhs\.gov|linearcity\.hk|youtube\.com|ptjaviergroup\.com|p4kurd\.com|tizag\.com|discoverbing\.com|devshed\.com|ashiyane\.org|owasp\.org|1923turk\.com|fictionbook\.org|silenthacker\.do\.am|v4-team\.com|codingforums\.com|tudosobrehacker\.com|zymic\.com|forums\.whirlpool\.net\.au|gaza-hacker\.com|immortaltechnique\.co\.uk|w3schools\.com|phpeasystep\.com|mcafee\.com|specialinterestarms\.com|pastesite\.com|pastebin\.com|joomla\.org|joomla\.fr|sourceforge\.net|joesjewelry\.com|twitter\.com/i
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

  # Excite Search Engine
  # Supposedly uses Google, Yahoo & Yandex Combined Search Results
  # Provides search query and we fetch link results
  # Return the links for first 15 pages as an array
  def excite_search(squery, verbose=true)
    if verbose
      $config['HTTP']['PROGRESS'] = true
    end
    searches=[]
    goodlinks=[]
    usablelinks=[]
    # Build our array of page requests links
    puts "[".light_blue + "*".white + "]".light_blue + " Searching via Excite....".white if verbose
    (0 .. 14).each { |x| searches << "http://msxml.excite.com/search/web?qsi=#{x}1&q=#{squery.gsub(' ', '%20')}" }
    # Curl's Multi::Mode for faster requests
    mresponses = @http.multi_get(searches)
    searches.each do |url|
      page = Nokogiri::HTML(mresponses[url].body_str)
      possibles = page.css("a")
      possibles.select do |link|
        if link['href'] =~ /^(http.+)&ru=.+/
          u = URI.decode($1.to_s.sub('ccs.infospace.com/ClickHandler.ashx?du=', '').chomp)
          usablelinks << u unless u =~ /excite\.com|infospace\.com/
        end
      end
    end
    usablelinks = usablelinks.uniq
    usablelinks.each do |url|
      goodlinks << url unless url =~ /excite\.com|infospace\.com|baidu\.com|duckduckgo\.com|google\.com|ask\.com|msn\.com|microsoft\.com|bing\.com|yahoo\.com|live\.com|microsofttranslator\.com|irongeek\.com|tefneth-import\.com|hackforums\.net|freelancer\.com|facebook\.com|mozilla\.org|stackoverflow\.com|php\.net|wikipedia\.org|amazon\.com|4shared\.com|wordpress\.org|about\.com|phpbuilder\.com|phpnuke\.org|fbi\.gov|nasa\.gov|dhs\.gov|linearcity\.hk|youtube\.com|ptjaviergroup\.com|p4kurd\.com|tizag\.com|discoverbing\.com|devshed\.com|ashiyane\.org|owasp\.org|1923turk\.com|fictionbook\.org|silenthacker\.do\.am|v4-team\.com|codingforums\.com|tudosobrehacker\.com|zymic\.com|forums\.whirlpool\.net\.au|gaza-hacker\.com|immortaltechnique\.co\.uk|w3schools\.com|phpeasystep\.com|mcafee\.com|specialinterestarms\.com|pastesite\.com|pastebin\.com|joomla\.org|joomla\.fr|sourceforge\.net|joesjewelry\.com|twitter\.com/i
    end
    puts "   [".light_green + "+".white + "] ".light_green + "Unique Links: #{goodlinks.length}".white if verbose
    f=File.open("#{@@out}excite.search", 'w+')
    goodlinks.each { |x| f.puts x }
    f.close
    if verbose
      $config['HTTP']['PROGRESS'] = false
    end
    return goodlinks
  end

  # NO LONGER WORKING, HAVE TO RE-FIGURE OUT HOW TO PARSE THEIR NEW JS MAGIC......
  # Google Search Function
  # Provide search query and we fetch link results
  # Return the links for first 25 pages as an array of links
  def google_search(squery, verbose=true)
    print_error("Google Search is temporarily out of order....")
    print_error("Check back again soon....")
  end

  # HotBot Search Engine
  # Provides search query and we fetch link results
  # Return the links for first 15 pages as an array
  def hotbot_search(squery, verbose=true)
    if verbose
      $config['HTTP']['PROGRESS'] = true
    end
    searches=[]
    goodlinks=[]
    usablelinks=[]
    # Build our array of page requests links
    puts "[".light_blue + "*".white + "]".light_blue + " Searching via HotBot....".white if verbose
    (1 .. 15).each { |x| searches << "http://www.hotbot.com/search/web?pn=#{x}&q=#{squery.gsub(' ', '%20')}&keyvol=01a2a6a008fa20688487" }
    # Curl's Multi::Mode for faster requests
    mresponses = @http.multi_get(searches)
    searches.each do |url|
      page = Nokogiri::HTML(mresponses[url].body_str)
      possibles = page.css("a")
      possibles.select do |link|
        begin
	  url = URI.parse(link['href'])
	  if url.scheme == 'http' || url.scheme =='https'
	    usablelinks << link['href'] unless link['href'] =~ /lygo\.com/
	  end
	rescue URI::InvalidURIError => err 
	  # If bad link cause error cause its not a link dont freak out, just move on....
	end
      end
    end
    usablelinks = usablelinks.uniq
    usablelinks.each do |url|
      goodlinks << url unless url =~ /lygo\.com|excite\.com|infospace\.com|baidu\.com|duckduckgo\.com|google\.com|ask\.com|msn\.com|microsoft\.com|bing\.com|yahoo\.com|live\.com|microsofttranslator\.com|irongeek\.com|tefneth-import\.com|hackforums\.net|freelancer\.com|facebook\.com|mozilla\.org|stackoverflow\.com|php\.net|wikipedia\.org|amazon\.com|4shared\.com|wordpress\.org|about\.com|phpbuilder\.com|phpnuke\.org|fbi\.gov|nasa\.gov|dhs\.gov|linearcity\.hk|youtube\.com|ptjaviergroup\.com|p4kurd\.com|tizag\.com|discoverbing\.com|devshed\.com|ashiyane\.org|owasp\.org|1923turk\.com|fictionbook\.org|silenthacker\.do\.am|v4-team\.com|codingforums\.com|tudosobrehacker\.com|zymic\.com|forums\.whirlpool\.net\.au|gaza-hacker\.com|immortaltechnique\.co\.uk|w3schools\.com|phpeasystep\.com|mcafee\.com|specialinterestarms\.com|pastesite\.com|pastebin\.com|joomla\.org|joomla\.fr|sourceforge\.net|joesjewelry\.com|twitter\.com/i
    end
    puts "   [".light_green + "+".white + "] ".light_green + "Unique Links: #{goodlinks.length}".white if verbose
    f=File.open("#{@@out}hotbot.search", 'w+')
    goodlinks.each { |x| f.puts x }
    f.close
    if verbose
      $config['HTTP']['PROGRESS'] = false
    end
    return goodlinks
  end

  # Yahoo! Search Engine
  # Provides search query and we fetch link results
  # Return the links for first 15 pages as an array
  def yahoo_search(squery, verbose=true)
    if verbose
      $config['HTTP']['PROGRESS'] = true
    end
    searches=[]
    goodlinks=[]
    usablelinks=[]
    # Build our array of page requests links
    puts "[".light_blue + "*".white + "]".light_blue + " Searching via Yahoo!....".white if verbose
    (0 .. 15).each { |x| searches << "http://search.yahoo.com/search;_ylt=AnMERt0QEqec72pVWttCN6ibvZx4?p=#{squery.gsub(' ', '%20')}&toggle=1&cop=mss&ei=UTF-8&fr=yfp-t-901&xargs=0&b=#{x}1&xa=aoLhm9a82kmZ1OfjB.suzA--,138886228" }
    # Curl's Multi::Mode for faster requests
    mresponses = @http.multi_get(searches)
    searches.each do |url|
      page = Nokogiri::HTML(mresponses[url].body_str)
      possibles = page.css("a")
      possibles.select do |link|
        if link['href'] =~ /\/r\/_ylt=.+;_ylu=.+\/EXP=\d+\/\*\*(http.+)/
          u = URI.decode($1.to_s.chomp)
          usablelinks << u unless u =~ /yahoo\.com|search\/srpcache/
        end
      end
    end
    usablelinks = usablelinks.uniq
    usablelinks.each do |url|
      goodlinks << url unless url =~ /baidu\.com|duckduckgo\.com|google\.com|ask\.com|msn\.com|microsoft\.com|bing\.com|yahoo\.com|live\.com|microsofttranslator\.com|irongeek\.com|tefneth-import\.com|hackforums\.net|freelancer\.com|facebook\.com|mozilla\.org|stackoverflow\.com|php\.net|wikipedia\.org|amazon\.com|4shared\.com|wordpress\.org|about\.com|phpbuilder\.com|phpnuke\.org|fbi\.gov|nasa\.gov|dhs\.gov|linearcity\.hk|youtube\.com|ptjaviergroup\.com|p4kurd\.com|tizag\.com|discoverbing\.com|devshed\.com|ashiyane\.org|owasp\.org|1923turk\.com|fictionbook\.org|silenthacker\.do\.am|v4-team\.com|codingforums\.com|tudosobrehacker\.com|zymic\.com|forums\.whirlpool\.net\.au|gaza-hacker\.com|immortaltechnique\.co\.uk|w3schools\.com|phpeasystep\.com|mcafee\.com|specialinterestarms\.com|pastesite\.com|pastebin\.com|joomla\.org|joomla\.fr|sourceforge\.net|joesjewelry\.com|twitter\.com/i
    end
    puts "   [".light_green + "+".white + "] ".light_green + "Unique Links: #{goodlinks.length}".white if verbose
    f=File.open("#{@@out}yahoo.search", 'w+')
    goodlinks.each { |x| f.puts x }
    f.close
    if verbose
      $config['HTTP']['PROGRESS'] = false
    end
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
