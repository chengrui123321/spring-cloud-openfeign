# Feign client 创建流程
	本流程仅包含 Feign.Builder#target()后续处理流程，前置流程参考本工程源码注释。

```java
class DefaultTargeter implements Targeter {
    
    	/**
    	 * 生成目标代理对象
    	 * @param factory FeignClientFactoryBean
    	 * @param feign Feign.Builder
    	 * @param context FeignContext
    	 * @param target Target
    	 * @return
    	 * @param <T>
    	 */
    	@Override
    	public <T> T target(FeignClientFactoryBean factory, Feign.Builder feign,
    			FeignContext context, Target.HardCodedTarget<T> target) {
    		// 创建动态代理对象
    		return feign.target(target);
    	}
    
    }
```
DefaultTargeter.java中调用 Feign.Builder.target(target), 源码如下:
```java
public static class Builder {
	// 构建 Feign 对象
	public Feign build() {
		SynchronousMethodHandler.Factory synchronousMethodHandlerFactory =
		  new SynchronousMethodHandler.Factory(client, retryer, requestInterceptors, logger,
			  logLevel, decode404, closeAfterDecode, propagationPolicy);
		ParseHandlersByName handlersByName =
		  new ParseHandlersByName(contract, options, encoder, decoder, queryMapEncoder,
			  errorDecoder, synchronousMethodHandlerFactory);
		// 创建 ReflectiveFeign，调用 ReflectiveFeign.target()
		return new ReflectiveFeign(handlersByName, invocationHandlerFactory, queryMapEncoder);
	}
	
	/**
	* 实例化目标对象
	* @param target 目标对象
	* @param <T>
	* @return 
	*/
	public <T> T target(Target<T> target) {
	  	return build().newInstance(target);
	}
}
```
build() 完成后，调用 ReflectiveFeign.newInstance()方法，源码如下：
```java
public class ReflectiveFeign extends Feign {
	public <T> T newInstance(Target<T> target) {
		// 通过 ParseHandlersByName 解析目标接口里面的方法
        Map<String, MethodHandler> nameToHandler = targetToHandlersByName.apply(target);
        // 最终保存的是方法和 MethodHandler 映射关系
        Map<Method, MethodHandler> methodToHandler = new LinkedHashMap<Method, MethodHandler>();
        List<DefaultMethodHandler> defaultMethodHandlers = new LinkedList<DefaultMethodHandler>();
    	// 遍历所有的方法
        for (Method method : target.type().getMethods()) {
        	// 如果方法是 Object 方法，跳过
          if (method.getDeclaringClass() == Object.class) {
            continue;
          } else if (Util.isDefault(method)) {
          	// 如果是默认接口中默认方法，创建 DefaultMethodHandler
            DefaultMethodHandler handler = new DefaultMethodHandler(method);
            defaultMethodHandlers.add(handler);
            methodToHandler.put(method, handler);
          } else {
          	// 保存 method:MethodHandler 映射关系
            methodToHandler.put(method, nameToHandler.get(Feign.configKey(target.type(), method)));
          }
        }
        // 创建 InvocationHandler，设置 目标对象和 method:MethodHandler 映射关系
        InvocationHandler handler = factory.create(target, methodToHandler);
        // 创建动态代理类
        T proxy = (T) Proxy.newProxyInstance(target.type().getClassLoader(),
            new Class<?>[] {target.type()}, handler);
    
        // 绑定默认方法到代理类中
        for (DefaultMethodHandler defaultMethodHandler : defaultMethodHandlers) {
          defaultMethodHandler.bindTo(proxy);
        }
        return proxy;
      }
}
```
targetToHandlersByName.apply(target) 主要是获取方法名和 MethodHandler 映射关系，每个方法都会创建一个 MethodHandler，
因为每个方法的参数属性不一致，需要单独维护。
总的来说，targetToHandlersByName.apply(target) :根据Contract协议规则，解析接口类的注解信息，
解析成内部表现：targetToHandlersByName.apply(target);会解析接口方法上的注解，从而解析出方法粒度的特定的配置信息，
然后生产一个SynchronousMethodHandler 然后需要维护一个<method，MethodHandler>的map，
放入InvocationHandler的实现FeignInvocationHandler中。代码如下:
```java
public class ReflectiveFeign extends Feign {
	public Map<String, MethodHandler> apply(Target key) {
		// 通过模板转换目标接口中的方法元数据集合，模板默认是 SpringMVC contract, 就是说接口方法需要和 spring mvc 中方法语法一致
      List<MethodMetadata> metadata = contract.parseAndValidatateMetadata(key.type());
      Map<String, MethodHandler> result = new LinkedHashMap<String, MethodHandler>();
      // 遍历元数据
      for (MethodMetadata md : metadata) {
        BuildTemplateByResolvingArgs buildTemplate;
        if (!md.formParams().isEmpty() && md.template().bodyTemplate() == null) {
          buildTemplate = new BuildFormEncodedTemplateFromArgs(md, encoder, queryMapEncoder);
        } else if (md.bodyIndex() != null) {
          buildTemplate = new BuildEncodedTemplateFromArgs(md, encoder, queryMapEncoder);
        } else {
          buildTemplate = new BuildTemplateByResolvingArgs(md, queryMapEncoder);
        }
        // 创建 MethodHandler, 并保存到 Map<String, MethodHandler> 中
        result.put(md.configKey(),
            // 创建 MethodHandler
            factory.create(key, md, buildTemplate, options, decoder, errorDecoder));
      }
      return result;
    }
}
```
factory.create(key, md, buildTemplate, options, decoder, errorDecoder)) 代表根据方法元数据创建对应的 MethodHandler, 保存每个方法信息，
由 SynchronousMethodHandler.Factory.create 进行创建，代码如下：
```java
static class Factory {

    private final Client client;
    private final Retryer retryer;
    private final List<RequestInterceptor> requestInterceptors;
    private final Logger logger;
    private final Logger.Level logLevel;
    private final boolean decode404;
    private final boolean closeAfterDecode;
    private final ExceptionPropagationPolicy propagationPolicy;

    Factory(Client client, Retryer retryer, List<RequestInterceptor> requestInterceptors,
        Logger logger, Logger.Level logLevel, boolean decode404, boolean closeAfterDecode,
        ExceptionPropagationPolicy propagationPolicy) {
      this.client = checkNotNull(client, "client");
      this.retryer = checkNotNull(retryer, "retryer");
      this.requestInterceptors = checkNotNull(requestInterceptors, "requestInterceptors");
      this.logger = checkNotNull(logger, "logger");
      this.logLevel = checkNotNull(logLevel, "logLevel");
      this.decode404 = decode404;
      this.closeAfterDecode = closeAfterDecode;
      this.propagationPolicy = propagationPolicy;
    }

	// 创建 MethodHandler，默认是 SynchronousMethodHandler
    public MethodHandler create(Target<?> target,
                                MethodMetadata md,
                                RequestTemplate.Factory buildTemplateFromArgs,
                                Options options,
                                Decoder decoder,
                                ErrorDecoder errorDecoder) {
      return new SynchronousMethodHandler(target, client, retryer, requestInterceptors, logger,
          logLevel, md, buildTemplateFromArgs, options, decoder,
          errorDecoder, decode404, closeAfterDecode, propagationPolicy);
    }
  }
```
将创建好的 MethodHandler 设置到保存，通过 InvocationHandlerFactory.create(target, methodToHandler) 创建InvocationHandler，默认实现类为 FeignInvocationHandler
通过 InvocationHandler 创建代理对象。后续调用 Feign 的时候会调用 FeignInvocationHandler.invoke()执行方法。


# Feign 调用方法执行流程
上面已经了解了最终创建的动态代理对象是 FeignInvocationHandler，执行方法的时候就是调用 invoke() 方法，代码如下:
```java
static class FeignInvocationHandler implements InvocationHandler {

    private final Target target;
    private final Map<Method, MethodHandler> dispatch;

    FeignInvocationHandler(Target target, Map<Method, MethodHandler> dispatch) {
      this.target = checkNotNull(target, "target");
      this.dispatch = checkNotNull(dispatch, "dispatch for %s", target);
    }
	// 执行代理方法
    @Override
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
    	// 判断是否默认方法
      if ("equals".equals(method.getName())) {
        try {
          Object otherHandler =
              args.length > 0 && args[0] != null ? Proxy.getInvocationHandler(args[0]) : null;
          return equals(otherHandler);
        } catch (IllegalArgumentException e) {
          return false;
        }
      } else if ("hashCode".equals(method.getName())) {
        return hashCode();
      } else if ("toString".equals(method.getName())) {
        return toString();
      }
		// dispatch.get(method) 获取一个 SynchronousMethodHandler，调用 invoke() 方法
      return dispatch.get(method).invoke(args);
    }
}
```
SynchronousMethodHandler.invoke() 调用流程如下：
```java
final class SynchronousMethodHandler implements MethodHandler {
	// 执行代理方法
  public Object invoke(Object[] argv) throws Throwable {
  	// 创建 RequestTemplate，请求模板
    RequestTemplate template = buildTemplateFromArgs.create(argv);
    Options options = findOptions(argv);
    Retryer retryer = this.retryer.clone();
    while (true) {
      try {
      	// 执行并且解码
        return executeAndDecode(template, options);
      } catch (RetryableException e) {
        try {
          retryer.continueOrPropagate(e);
        } catch (RetryableException th) {
          Throwable cause = th.getCause();
          if (propagationPolicy == UNWRAP && cause != null) {
            throw cause;
          } else {
            throw th;
          }
        }
        if (logLevel != Logger.Level.NONE) {
          logger.logRetry(metadata.configKey(), logLevel);
        }
        continue;
      }
    }
  }
  
  // 执行并且解码
  Object executeAndDecode(RequestTemplate template, Options options) throws Throwable {
  	// 将 RequestTemplate 请求模板转为 Request
    Request request = targetRequest(template);
    if (logLevel != Logger.Level.NONE) {
      logger.logRequest(metadata.configKey(), logLevel, request);
    }

    Response response;
    long start = System.nanoTime();
    try {
    	// 通过 client 执行，此时的 client 为 LoadBalancerFeignClient
      response = client.execute(request, options);
    } catch (IOException e) {
      if (logLevel != Logger.Level.NONE) {
        logger.logIOException(metadata.configKey(), logLevel, e, elapsedTime(start));
      }
      throw errorExecuting(request, e);
    }
    long elapsedTime = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);

    boolean shouldClose = true;
    try {
      if (logLevel != Logger.Level.NONE) {
        response =
            logger.logAndRebufferResponse(metadata.configKey(), logLevel, response, elapsedTime);
      }
      if (Response.class == metadata.returnType()) {
        if (response.body() == null) {
          return response;
        }
        if (response.body().length() == null ||
            response.body().length() > MAX_RESPONSE_BUFFER_SIZE) {
          shouldClose = false;
          return response;
        }
        // Ensure the response body is disconnected
        byte[] bodyData = Util.toByteArray(response.body().asInputStream());
        return response.toBuilder().body(bodyData).build();
      }
      if (response.status() >= 200 && response.status() < 300) {
        if (void.class == metadata.returnType()) {
          return null;
        } else {
          Object result = decode(response);
          shouldClose = closeAfterDecode;
          return result;
        }
      } else if (decode404 && response.status() == 404 && void.class != metadata.returnType()) {
        Object result = decode(response);
        shouldClose = closeAfterDecode;
        return result;
      } else {
        throw errorDecoder.decode(metadata.configKey(), response);
      }
    } catch (IOException e) {
      if (logLevel != Logger.Level.NONE) {
        logger.logIOException(metadata.configKey(), logLevel, e, elapsedTime);
      }
      throw errorReading(request, response, e);
    } finally {
      if (shouldClose) {
        ensureClosed(response.body());
      }
    }
  }
}
```
真正执行请求方法的逻辑在 LoadBalancerFeignClient.execute 中，源码如下：
```java
public class LoadBalancerFeignClient implements Client {
	/**
	 * 委派客户端
	 * 真正执行请求的客户端
	 */
	private final Client delegate;
	
	public Response execute(Request request, Request.Options options) throws IOException {
    		try {
    			// 获取请求 url
    			URI asUri = URI.create(request.url());
    			String clientName = asUri.getHost();
    			URI uriWithoutHost = cleanUrl(request.url(), clientName);
    			// 包装成 RibbonRequest
    			FeignLoadBalancer.RibbonRequest ribbonRequest = new FeignLoadBalancer.RibbonRequest(
    					this.delegate, request, uriWithoutHost);
    
    			IClientConfig requestConfig = getClientConfig(options, clientName);
    			// lbClient(clientName) 获取 FeignLoadBalancer（本质上还是 ZoneAwareLoadBalancer）进行包装
    			// 执行方法，通过 AbstractLoadBalancerAwareClient.executeWithLoadBalancer() 方法
    			return lbClient(clientName)
    					.executeWithLoadBalancer(ribbonRequest, requestConfig).toResponse();
    		}
    		catch (ClientException e) {
    			IOException io = findIOException(e);
    			if (io != null) {
    				throw io;
    			}
    			throw new RuntimeException(e);
    		}
    	}
}
```
AbstractLoadBalancerAwareClient.executeWithLoadBalancer() 源码如下：
```java
public abstract class AbstractLoadBalancerAwareClient<S extends ClientRequest, T extends IResponse> extends LoadBalancerContext implements IClient<S, T>, IClientConfigAware {
	// 基于负载均衡的方式执行目标方法
	public T executeWithLoadBalancer(final S request, final IClientConfig requestConfig) throws ClientException {
            LoadBalancerCommand<T> command = buildLoadBalancerCommand(request, requestConfig);
    
            try {
            	// submit（）方法中会选择执行的服务
                return command.submit(
                    new ServerOperation<T>() {
                    	// 获取服务后执行调用
                        @Override
                        public Observable<T> call(Server server) {
                            URI finalUri = reconstructURIWithServer(server, request.getUri());
                            S requestForServer = (S) request.replaceUri(finalUri);
                            try {
                                return Observable.just(AbstractLoadBalancerAwareClient.this.execute(requestForServer, requestConfig));
                            } 
                            catch (Exception e) {
                                return Observable.error(e);
                            }
                        }
                    })
                    .toBlocking()
                    .single();
            } catch (Exception e) {
                Throwable t = e.getCause();
                if (t instanceof ClientException) {
                    throw (ClientException) t;
                } else {
                    throw new ClientException(e);
                }
            }
            
        }
}
```
上面的代码里先通过 LoadBalancerCommand.submit() 获取服务，代码如下：
```java
public class LoadBalancerCommand {
public Observable<T> submit(final ServerOperation<T> operation) {
	// Use the load balancer
            Observable<T> o = 
            		// selectServer() 方法就是选择一个服务
                    (server == null ? selectServer() : Observable.just(server))
                    .concatMap(new Func1<Server, Observable<T>>() {
                        @Override
                        // Called for each server being selected
                        public Observable<T> call(Server server) {
                            context.setServer(server);
                            final ServerStats stats = loadBalancerContext.getServerStats(server);
                            
                            // Called for each attempt and retry
                            Observable<T> o = Observable
                                    .just(server)
                                    .concatMap(new Func1<Server, Observable<T>>() {
                                        @Override
                                        public Observable<T> call(final Server server) {
                                            context.incAttemptCount();
                                            loadBalancerContext.noteOpenConnection(stats);
                                            
                                            if (listenerInvoker != null) {
                                                try {
                                                    listenerInvoker.onStartWithServer(context.toExecutionInfo());
                                                } catch (AbortExecutionException e) {
                                                    return Observable.error(e);
                                                }
                                            }
                                            
                                            final Stopwatch tracer = loadBalancerContext.getExecuteTracer().start();
                                            
                                            return operation.call(server).doOnEach(new Observer<T>() {
                                                private T entity;
                                                @Override
                                                public void onCompleted() {
                                                    recordStats(tracer, stats, entity, null);
                                                    // TODO: What to do if onNext or onError are never called?
                                                }
    
                                                @Override
                                                public void onError(Throwable e) {
                                                    recordStats(tracer, stats, null, e);
                                                    logger.debug("Got error {} when executed on server {}", e, server);
                                                    if (listenerInvoker != null) {
                                                        listenerInvoker.onExceptionWithServer(e, context.toExecutionInfo());
                                                    }
                                                }
    
                                                @Override
                                                public void onNext(T entity) {
                                                    this.entity = entity;
                                                    if (listenerInvoker != null) {
                                                        listenerInvoker.onExecutionSuccess(entity, context.toExecutionInfo());
                                                    }
                                                }                            
                                                
                                                private void recordStats(Stopwatch tracer, ServerStats stats, Object entity, Throwable exception) {
                                                    tracer.stop();
                                                    loadBalancerContext.noteRequestCompletion(stats, entity, exception, tracer.getDuration(TimeUnit.MILLISECONDS), retryHandler);
                                                }
                                            });
                                        }
                                    });
                            
                            if (maxRetrysSame > 0) 
                                o = o.retry(retryPolicy(maxRetrysSame, true));
                            return o;
                        }
                    });
            
	}
	// 基于负载均衡选择服务
	private Observable<Server> selectServer() {
		return Observable.create(new OnSubscribe<Server>() {
			@Override
			public void call(Subscriber<? super Server> next) {
				try {
					// 获取一个服务
					Server server = loadBalancerContext.getServerFromLoadBalancer(loadBalancerURI, loadBalancerKey);   
					next.onNext(server);
					next.onCompleted();
				} catch (Exception e) {
					next.onError(e);
				}
			}
		});
	}
}
```
真正选择一个服务的逻辑是在 LoadBalancerContext.getServerFromLoadBalancer()，代码如下：
```java
public class LoadBalancerContext {
	// 获取服务
	public Server getServerFromLoadBalancer(@Nullable URI original, @Nullable Object loadBalancerKey) throws ClientException {
		String host = null;
		int port = -1;
		if (original != null) {
			host = original.getHost();
		}
		if (original != null) {
			Pair<String, Integer> schemeAndPort = deriveSchemeAndPortFromPartialUri(original);        
			port = schemeAndPort.second();
		}

		// Various Supported Cases
		// The loadbalancer to use and the instances it has is based on how it was registered
		// In each of these cases, the client might come in using Full Url or Partial URL
		// 获取负载均衡器，默认 为 ZoneAwareLoadBalancer
		ILoadBalancer lb = getLoadBalancer();
		if (host == null) {
			// Partial URI or no URI Case
			// well we have to just get the right instances from lb - or we fall back
			if (lb != null){
				Server svc = lb.chooseServer(loadBalancerKey);
				if (svc == null){
					throw new ClientException(ClientException.ErrorType.GENERAL,
							"Load balancer does not have available server for client: "
									+ clientName);
				}
				host = svc.getHost();
				if (host == null){
					throw new ClientException(ClientException.ErrorType.GENERAL,
							"Invalid Server for :" + svc);
				}
				logger.debug("{} using LB returned Server: {} for request {}", new Object[]{clientName, svc, original});
				return svc;
			} else {
				// No Full URL - and we dont have a LoadBalancer registered to
				// obtain a server
				// if we have a vipAddress that came with the registration, we
				// can use that else we
				// bail out
				if (vipAddresses != null && vipAddresses.contains(",")) {
					throw new ClientException(
							ClientException.ErrorType.GENERAL,
							"Method is invoked for client " + clientName + " with partial URI of ("
							+ original
							+ ") with no load balancer configured."
							+ " Also, there are multiple vipAddresses and hence no vip address can be chosen"
							+ " to complete this partial uri");
				} else if (vipAddresses != null) {
					try {
						Pair<String,Integer> hostAndPort = deriveHostAndPortFromVipAddress(vipAddresses);
						host = hostAndPort.first();
						port = hostAndPort.second();
					} catch (URISyntaxException e) {
						throw new ClientException(
								ClientException.ErrorType.GENERAL,
								"Method is invoked for client " + clientName + " with partial URI of ("
								+ original
								+ ") with no load balancer configured. "
								+ " Also, the configured/registered vipAddress is unparseable (to determine host and port)");
					}
				} else {
					throw new ClientException(
							ClientException.ErrorType.GENERAL,
							this.clientName
							+ " has no LoadBalancer registered and passed in a partial URL request (with no host:port)."
							+ " Also has no vipAddress registered");
				}
			}
		} else {
			// Full URL Case
			// This could either be a vipAddress or a hostAndPort or a real DNS
			// if vipAddress or hostAndPort, we just have to consult the loadbalancer
			// but if it does not return a server, we should just proceed anyways
			// and assume its a DNS
			// For restClients registered using a vipAddress AND executing a request
			// by passing in the full URL (including host and port), we should only
			// consult lb IFF the URL passed is registered as vipAddress in Discovery
			boolean shouldInterpretAsVip = false;

			if (lb != null) {
				shouldInterpretAsVip = isVipRecognized(original.getAuthority());
			}
			if (shouldInterpretAsVip) {
				Server svc = lb.chooseServer(loadBalancerKey);
				if (svc != null){
					host = svc.getHost();
					if (host == null){
						throw new ClientException(ClientException.ErrorType.GENERAL,
								"Invalid Server for :" + svc);
					}
					logger.debug("using LB returned Server: {} for request: {}", svc, original);
					return svc;
				} else {
					// just fall back as real DNS
					logger.debug("{}:{} assumed to be a valid VIP address or exists in the DNS", host, port);
				}
			} else {
				// consult LB to obtain vipAddress backed instance given full URL
				//Full URL execute request - where url!=vipAddress
				logger.debug("Using full URL passed in by caller (not using load balancer): {}", original);
			}
		}
		// end of creating final URL
		if (host == null){
			throw new ClientException(ClientException.ErrorType.GENERAL,"Request contains no HOST to talk to");
		}
		// just verify that at this point we have a full URL

		return new Server(host, port);
	}
}
```
获取服务的后续流程走的是 Ribbon 的流程，原理详见 Ribbon 源码分析部分。
获取到服务之后，会回调 AbstractLoadBalancerAwareClient.executeWithLoadBalancer().call() 方法进行请求，最终会调用 AbstractLoadBalancerAwareClient.this.execute(requestForServer, requestConfig) 方法执行请求，
会进入 FeignLoadBalancer.execute() 方法，代码如下：
````java
public class FeignLoadBalancer {
	
	// 执行请求
	@Override
	public RibbonResponse execute(RibbonRequest request, IClientConfig configOverride)
			throws IOException {
		Request.Options options;
		if (configOverride != null) {
			RibbonProperties override = RibbonProperties.from(configOverride);
			options = new Request.Options(override.connectTimeout(this.connectTimeout),
					override.readTimeout(this.readTimeout));
		}
		else {
			options = new Request.Options(this.connectTimeout, this.readTimeout);
		}
		// 获取 LoadBalancerFeignClient.execute() 进行请求
		Response response = request.client().execute(request.toRequest(), options);
		return new RibbonResponse(request.getUri(), response);
	}
}	
````
request.client() 会获取最终执行的客户端，默认的是 feign.Client.Default，代码如下：
```java
public class Default implements Client {
	// 执行
	@Override
	public Response execute(Request request, Options options) throws IOException {
		// 转换请求并发送请求，基于 HttpURLConnection 方式直接请求
	  HttpURLConnection connection = convertAndSend(request, options);
	  // 转换响应结果
	  return convertResponse(connection, request);
	}

	// 转换请求并发送请求，基于 HttpURLConnection
	HttpURLConnection convertAndSend(Request request, Options options) throws IOException {
      final URL url = new URL(request.url());
      final HttpURLConnection connection = this.getConnection(url);
      if (connection instanceof HttpsURLConnection) {
        HttpsURLConnection sslCon = (HttpsURLConnection) connection;
        if (sslContextFactory != null) {
          sslCon.setSSLSocketFactory(sslContextFactory);
        }
        if (hostnameVerifier != null) {
          sslCon.setHostnameVerifier(hostnameVerifier);
        }
      }
      connection.setConnectTimeout(options.connectTimeoutMillis());
      connection.setReadTimeout(options.readTimeoutMillis());
      connection.setAllowUserInteraction(false);
      connection.setInstanceFollowRedirects(options.isFollowRedirects());
      connection.setRequestMethod(request.httpMethod().name());

      Collection<String> contentEncodingValues = request.headers().get(CONTENT_ENCODING);
      boolean gzipEncodedRequest =
          contentEncodingValues != null && contentEncodingValues.contains(ENCODING_GZIP);
      boolean deflateEncodedRequest =
          contentEncodingValues != null && contentEncodingValues.contains(ENCODING_DEFLATE);

      boolean hasAcceptHeader = false;
      Integer contentLength = null;
      for (String field : request.headers().keySet()) {
        if (field.equalsIgnoreCase("Accept")) {
          hasAcceptHeader = true;
        }
        for (String value : request.headers().get(field)) {
          if (field.equals(CONTENT_LENGTH)) {
            if (!gzipEncodedRequest && !deflateEncodedRequest) {
              contentLength = Integer.valueOf(value);
              connection.addRequestProperty(field, value);
            }
          } else {
            connection.addRequestProperty(field, value);
          }
        }
      }
      // Some servers choke on the default accept string.
      if (!hasAcceptHeader) {
        connection.addRequestProperty("Accept", "*/*");
      }

      if (request.requestBody().asBytes() != null) {
        if (contentLength != null) {
          connection.setFixedLengthStreamingMode(contentLength);
        } else {
          connection.setChunkedStreamingMode(8196);
        }
        connection.setDoOutput(true);
        OutputStream out = connection.getOutputStream();
        if (gzipEncodedRequest) {
          out = new GZIPOutputStream(out);
        } else if (deflateEncodedRequest) {
          out = new DeflaterOutputStream(out);
        }
        try {
          out.write(request.requestBody().asBytes());
        } finally {
          try {
            out.close();
          } catch (IOException suppressed) { // NOPMD
          }
        }
      }
      return connection;
    }
	// 转换响应结果
	Response convertResponse(HttpURLConnection connection, Request request) throws IOException {
	  int status = connection.getResponseCode();
	  String reason = connection.getResponseMessage();

	  if (status < 0) {
		throw new IOException(format("Invalid status(%s) executing %s %s", status,
			connection.getRequestMethod(), connection.getURL()));
	  }

	  Map<String, Collection<String>> headers = new LinkedHashMap<>();
	  for (Map.Entry<String, List<String>> field : connection.getHeaderFields().entrySet()) {
		// response message
		if (field.getKey() != null) {
		  headers.put(field.getKey(), field.getValue());
		}
	  }

	  Integer length = connection.getContentLength();
	  if (length == -1) {
		length = null;
	  }
	  InputStream stream;
	  if (status >= 400) {
		stream = connection.getErrorStream();
	  } else {
		stream = connection.getInputStream();
	  }
	  // 构建响应结果
	  return Response.builder()
		  .status(status)
		  .reason(reason)
		  .headers(headers)
		  .request(request)
		  .body(stream, length)
		  .build();
	}
}
```
到此，调用流程源码已经结束。

Spring Cloud OpenFeign 的核心工作原理经上文探究可以非常简单的总结为：

1.通过 @EnableFeignClients 触发 Spring 应用程序对 classpath 中 @FeignClient 修饰类的扫描
2.解析到 @FeignClient 修饰类后， Feign 框架通过扩展 Spring Bean Definition 的注册逻辑， 最终注册一个 FeignClientFactoryBean 进入 Spring 容器
3.Spring 容器在初始化其他用到 @FeignClient 接口的类时， 获得的是 FeignClientFactryBean 产生的一个代理对象 Proxy.
4.基于 java 原生的动态代理机制， 针对 Proxy 的调用， 都会被统一转发给 Feign 框架所定义的一个 InvocationHandler ， 由该 Handler 完成后续的 HTTP 转换， 发送， 接收， 翻译HTTP响应的工作。
