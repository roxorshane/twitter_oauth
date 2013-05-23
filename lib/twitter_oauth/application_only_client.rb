module TwitterOAuth
  class ApplicationOnlyClient

    def initialize(opts = {})
      @consumer_key    = opts[:consumer_key]
      @consumer_secret = opts[:consumer_secret]
      @api_host        = opts[:api_host] || 'api.twitter.com'
      @api_version     = opts[:api_version] || '1.1'
    end

    def show(username)
      get "/#{@api_version}/users/show/#{username}.json", {
        "Authorization" => "Bearer #{bearer_token}"
      }
    end

    private

    def bearer_token
      response = post "/oauth2/token", { "grant_type" => "client_credentials" }, {
        "Authorization" => "Basic #{encoded_key_secret_value}",
        "Content-Type"  => "application/x-www-form-urlencoded;charset=UTF-8"
      }

      response["access_token"]
    end

    def get(path, headers={})
      request :method  => :get,
              :path    => path,
              :headers => headers
    end

    def post(path, data, headers={})
      request :method  => :post,
              :path    => path,
              :data    => data,
              :headers => headers
    end

    def request(opts)
      method   = opts[:method]
      protocol = opts[:protocol] || 'https'
      path     = opts[:path]
      host     = opts[:host] || @api_host
      headers  = opts[:headers] || {}
      data     = opts[:data] || {}

      uri = URI.parse "#{protocol}://#{host}#{path}"

      http = Net::HTTP.new uri.host, uri.port
      http.use_ssl = true

      headers.merge!({
        "User-Agent" => "twitter_oauth gem v#{TwitterOAuth::VERSION}"
      })

      case method.to_sym
      when :get
        request = Net::HTTP::Get.new uri.request_uri, headers
      when :post
        request = Net::HTTP::Post.new uri.request_uri, headers
        request.set_form_data data
      end

      JSON.parse http.request(request).body
    end

    def encoded_key_secret_value
      Base64.encode64(@consumer_key + ":" + @consumer_secret).gsub("\n", "")
    end

  end
end
