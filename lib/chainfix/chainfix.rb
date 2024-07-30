module ChainFix
  BASE_DIR = File.join(File.basename(__file__), '..')
  autoload :Config, 'chainfix/config'
  autoload :Command, 'chainfix/command'
end