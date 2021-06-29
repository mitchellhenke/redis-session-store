require 'redis'
require 'rack'
require 'active_support/core_ext/hash/indifferent_access'
require 'active_support/core_ext/object'

# Redis session storage for Rails, and for Rails only. Derived from
# the MemCacheStore code, simply dropping in Redis instead.
class RedisSessionStore < ActionDispatch::Session::AbstractSecureStore
  # ==== Options
  # * +:key+ - Same as with the other cookie stores, key name
  # * +:redis+ - A hash with redis-specific options
  #   * +:url+ - Redis url, default is redis://localhost:6379/0
  #   * +:key_prefix+ - Prefix for keys used in Redis, e.g. +myapp:+
  #   * +:expire_after+ - A number in seconds for session timeout
  #   * +:client+ - Connect to Redis with given object rather than create one
  # * +:on_redis_down:+ - Called with err, env, and SID on Errno::ECONNREFUSED
  # * +:on_session_load_error:+ - Called with err and SID on Marshal.load fail
  # * +:serializer:+ - Serializer to use on session data, default is :marshal.
  # * +:skip_identical_write:+ Boolean, saving of initial session state
  #
  # ==== Examples
  #
  #     Rails.application.config.session_store :redis_session_store, {
  #       key: 'your_session_key',
  #       redis: {
  #         expire_after: 120.minutes,
  #         key_prefix: 'myapp:session:',
  #         url: 'redis://localhost:6379/0'
  #       },
  #       on_redis_down: ->(*a) { logger.error("Redis down! #{a.inspect}") }
  #       serializer: :json
  #     }
  #
  def initialize(app, options = {})
    super

    redis_options = options[:redis] || {}

    @default_options[:namespace] = 'rack:session'
    @default_options.merge!(redis_options)
    @redis = redis_options[:client] || Redis.new(redis_options)
    @on_redis_down = options[:on_redis_down]
    @serializer = determine_serializer(options[:serializer])
    @on_session_load_error = options[:on_session_load_error]
    @skip_identical_write = options[:skip_identical_write]
    verify_handlers!
  end

  attr_accessor :on_redis_down, :on_session_load_error

  private

  attr_reader :redis, :key, :default_options, :serializer

  # overrides method defined in rack to actually verify session existence
  # Prevents needless new sessions from being created in scenario where
  # user HAS session id, but it already expired, or is invalid for some
  # other reason, and session was accessed only for reading.
  def session_exists?(env)
    value = current_session_id(env)

    value.present? && key_exists?(value)
  rescue Errno::ECONNREFUSED, Redis::CannotConnectError => e
    on_redis_down&.call(e, env, value)

    true
  end

  def key_exists?(value)
    redis.exists?(prefixed(value))
  end

  def verify_handlers!
    %w[on_redis_down on_session_load_error].each do |h|
      next unless (handler = public_send(h)) && !handler.respond_to?(:call)

      raise ArgumentError, "#{h} handler is not callable"
    end
  end

  def prefixed(sid)
    "#{default_options[:key_prefix]}#{sid}"
  end

  def session_default_values
    [generate_sid, {}.with_indifferent_access]
  end

  def get_session(env, sid)
    return session_default_values unless sid

    session = load_session_from_redis(sid)
    if session
      session = session_data(sid, session)
      [sid, session]
    else
      session_default_values
    end
  rescue Errno::ECONNREFUSED, Redis::CannotConnectError => e
    on_redis_down&.call(e, env, sid)
    session_default_values
  end
  alias find_session get_session

  def session_data(sid, session_data)
    if @skip_identical_write
      session_with_initial_state = session_data.clone
      session_with_initial_state['session_initial_state'] = session_data
      session_with_initial_state
    else
      session_data
    end
  end

  def load_session_from_redis(sid)
    data = redis.get(prefixed(sid))
    begin
      data ? decode(data) : nil
    rescue StandardError => e
      destroy_session_from_sid(sid, drop: true)
      on_session_load_error&.call(e, sid)
      nil
    end
  end

  def decode(data)
    session = serializer.load(data)
    session.with_indifferent_access
  end

  def set_session(env, sid, session_data, options = nil)
    if @skip_identical_write
      session_initial = session_data.delete 'session_initial_state'
      return sid if session_initial == session_data
    end

    expiry = get_expiry(env, options)
    if expiry
      redis.setex(prefixed(sid), expiry, encode(session_data))
    else
      redis.set(prefixed(sid), encode(session_data))
    end
    sid
  rescue Errno::ECONNREFUSED, Redis::CannotConnectError => e
    on_redis_down&.call(e, env, sid)
    false
  end
  alias write_session set_session

  def get_expiry(env, options)
    session_storage_options = options || env.fetch(Rack::RACK_SESSION_OPTIONS, {})
    session_storage_options[:ttl] || session_storage_options[:expire_after]
  end

  def encode(session_data)
    serializer.dump(session_data)
  end

  def destroy_session(env, sid, options)
    destroy_session_from_sid(sid, (options || {}).to_hash.merge(env: env))
  end
  alias delete_session destroy_session

  def destroy(env)
    if env['rack.request.cookie_hash'] &&
       (sid = env['rack.request.cookie_hash'][key])
      destroy_session_from_sid(sid, drop: true, env: env)
    end
    false
  end

  def destroy_session_from_sid(sid, options = {})
    redis.del(prefixed(sid))
    (options || {})[:drop] ? nil : generate_sid
  rescue Errno::ECONNREFUSED, Redis::CannotConnectError => e
    on_redis_down&.call(e, options[:env] || {}, sid)
  end

  def determine_serializer(serializer)
    serializer ||= :marshal
    case serializer
    when :marshal then Marshal
    when :json    then JsonSerializer
    else serializer
    end
  end

  # Uses built-in JSON library to encode/decode session
  class JsonSerializer
    def self.load(value)
      JSON.parse(value, quirks_mode: true)
    end

    def self.dump(value)
      JSON.generate(value, quirks_mode: true)
    end
  end
end
