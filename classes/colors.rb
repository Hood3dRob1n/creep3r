# Colors 
# Thanks to KINGSABRI for helping drop gem dependencies for colorize
# Simply open up String class and add in functions to make it possible

class String
  # Apply color to full text
  def colorize(text, color_code)
    "#{color_code}#{text}\033[0m"
  end

  def white
    colorize(self, "\033[1m\033[97m")
  end

  def red
    colorize(self, "\033[31m")
  end

  def light_red
    colorize(self, "\033[1m\033[31m")
  end

  def green
    colorize(self, "\033[32m")
  end

  def light_green
    colorize(self, "\033[1m\033[32m")
  end

  def yellow
    colorize(self, "\033[33m")
  end

  def light_yellow
    colorize(self, "\033[1m\033[33m")
  end

  def blue
    colorize(self, "\033[34m")
  end

  def light_blue
    colorize(self, "\033[1m\033[34m")
  end

  def purple
    colorize(self, "\033[35m")
  end

  def light_purple
    colorize(self, "\033[1m\033[35m")
  end

  def cyan
    colorize(self, "\033[0;36;49m")
  end

  def light_cyan
    colorize(self, "\033[1m\033[36m")
  end

  def bold
    colorize(self, "\033[1m")
  end

  def underline
    colorize(self, "\033[4m")
  end

  def blink
    colorize(self, "\033[5m")
  end
end
