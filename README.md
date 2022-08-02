![Ruby](https://github.com/kwent/omniauth-goto/workflows/Ruby/badge.svg?branch=master)

# OmniAuth GoTo

This is the official OmniAuth strategy for authenticating to GoTo. To
use it, you'll need to sign up for an OAuth2 Client ID and Secret
on the [GoTo Developer Page](https://developer.logmeininc.com/clients).

## Installation

```ruby
gem 'omniauth-goto'
```

## Basic Usage

```ruby
use OmniAuth::Builder do
  provider :goto, ENV['GOTO_CLIENT_ID'], ENV['GOTO_CLIENT_SECRET']
end
```

## Basic Usage Rails

In `config/initializers/goto.rb`

```ruby
  Rails.application.config.middleware.use OmniAuth::Builder do
    provider :goto, ENV['GOTO_CLIENT_ID'], ENV['GOTO_CLIENT_SECRET']
  end
```

## Dynamic client_id and client_secret

In `config/initializers/goto.rb`

```ruby
Rails.application.config.middleware.use OmniAuth::Builder do
  setup_proc = lambda do |env|
    req = Rack::Request.new(env)
    env['omniauth.strategy'].options[:client_id] = req.params['client_id']
    env['omniauth.strategy'].options[:client_secret] = req.params['client_secret']
  end
  provider :goto, nil, nil, { setup: setup_proc }
end
```

More info: https://github.com/omniauth/omniauth/wiki/Setup-Phase

## Semver

This project adheres to Semantic Versioning 2.0.0. Any violations of this scheme are considered to be bugs.
All changes will be tracked [here](https://github.com/kwent/omniauth-goto/releases).

## License

Copyright (c) 2022 Quentin Rousseau.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
