/*
 * Copyright 2013-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.cloud.openfeign;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.beans.factory.annotation.AnnotatedBeanDefinition;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.BeanDefinitionHolder;
import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.BeanDefinitionReaderUtils;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.context.EnvironmentAware;
import org.springframework.context.ResourceLoaderAware;
import org.springframework.context.annotation.ClassPathScanningCandidateComponentProvider;
import org.springframework.context.annotation.ImportBeanDefinitionRegistrar;
import org.springframework.core.annotation.AnnotationAttributes;
import org.springframework.core.env.Environment;
import org.springframework.core.io.ResourceLoader;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.core.type.ClassMetadata;
import org.springframework.core.type.classreading.MetadataReader;
import org.springframework.core.type.classreading.MetadataReaderFactory;
import org.springframework.core.type.filter.AbstractClassTestingTypeFilter;
import org.springframework.core.type.filter.AnnotationTypeFilter;
import org.springframework.core.type.filter.TypeFilter;
import org.springframework.util.Assert;
import org.springframework.util.ClassUtils;
import org.springframework.util.StringUtils;

/**
 * @author Spencer Gibb
 * @author Jakub Narloch
 * @author Venil Noronha
 * @author Gang Li
 *
 * 实现 {@link ImportBeanDefinitionRegistrar}, {@link ImportBeanDefinitionRegistrar#registerBeanDefinitions(AnnotationMetadata, BeanDefinitionRegistry)} 可以注册指定的 BeanDefinition 信息
 * 主要是扫描 FeignClient 客户端，并生成动态代理类注入容器中
 */
class FeignClientsRegistrar
		implements ImportBeanDefinitionRegistrar, ResourceLoaderAware, EnvironmentAware {

	// patterned after Spring Integration IntegrationComponentScanRegistrar
	// and RibbonClientsConfigurationRegistgrar

	/**
	 * 资源加载器，用于加载指定 {@link org.springframework.core.io.Resource}
	 */
	private ResourceLoader resourceLoader;

	/**
	 * 环境信息，Spring 中所有配置文件最终都会加入环境中
	 * {@link org.springframework.core.env.PropertySource} 代表每个配置文件配置信息
	 * {@link org.springframework.core.env.MutablePropertySources} 代表多个配置信息
	 */
	private Environment environment;

	FeignClientsRegistrar() {
	}

	static void validateFallback(final Class clazz) {
		Assert.isTrue(!clazz.isInterface(),
				"Fallback class must implement the interface annotated by @FeignClient");
	}

	static void validateFallbackFactory(final Class clazz) {
		Assert.isTrue(!clazz.isInterface(), "Fallback factory must produce instances "
				+ "of fallback classes that implement the interface annotated by @FeignClient");
	}

	/**
	 * 获取名称，并更新 url
	 * @param name
	 * @return
	 */
	static String getName(String name) {
		if (!StringUtils.hasText(name)) {
			return "";
		}

		String host = null;
		try {
			String url;
			if (!name.startsWith("http://") && !name.startsWith("https://")) {
				url = "http://" + name;
			}
			else {
				url = name;
			}
			host = new URI(url).getHost();

		}
		catch (URISyntaxException e) {
		}
		Assert.state(host != null, "Service id not legal hostname (" + name + ")");
		return name;
	}

	static String getUrl(String url) {
		if (StringUtils.hasText(url) && !(url.startsWith("#{") && url.contains("}"))) {
			if (!url.contains("://")) {
				url = "http://" + url;
			}
			try {
				new URL(url);
			}
			catch (MalformedURLException e) {
				throw new IllegalArgumentException(url + " is malformed", e);
			}
		}
		return url;
	}

	static String getPath(String path) {
		if (StringUtils.hasText(path)) {
			path = path.trim();
			if (!path.startsWith("/")) {
				path = "/" + path;
			}
			if (path.endsWith("/")) {
				path = path.substring(0, path.length() - 1);
			}
		}
		return path;
	}

	/**
	 * {@link ResourceLoaderAware#setResourceLoader(ResourceLoader)} 回调，设置资源加载器
	 * @param resourceLoader the ResourceLoader object to be used by this object
	 */
	@Override
	public void setResourceLoader(ResourceLoader resourceLoader) {
		this.resourceLoader = resourceLoader;
	}

	/**
	 * 基于 {@link BeanDefinitionRegistry#registerBeanDefinition(String, BeanDefinition)} 注册 BeanDefinition
	 * @param metadata annotation metadata of the importing class
	 * @param registry current bean definition registry
	 */
	@Override
	public void registerBeanDefinitions(AnnotationMetadata metadata,
			BeanDefinitionRegistry registry) {
		// 注册默认配置信息
		registerDefaultConfiguration(metadata, registry);
		// 注册 FeignClient 客户端
		registerFeignClients(metadata, registry);
	}

	/**
	 * 注册默认配置信息
	 * @param metadata 注解元数据，可以获取注解中配置的参数信息
	 * @param registry BeanDefinitionRegistry
	 */
	private void registerDefaultConfiguration(AnnotationMetadata metadata,
			BeanDefinitionRegistry registry) {
		// 获取 @EnableFeignClients 注解元数据信息
		Map<String, Object> defaultAttrs = metadata
				.getAnnotationAttributes(EnableFeignClients.class.getName(), true);
		// 如果有配置信息，并且配置了 defaultConfiguration 属性，获取指定的配置，此时基于 FeignClientsConfiguration
		if (defaultAttrs != null && defaultAttrs.containsKey("defaultConfiguration")) {
			String name;
			if (metadata.hasEnclosingClass()) {
				name = "default." + metadata.getEnclosingClassName();
			}
			else {
				name = "default." + metadata.getClassName();
			}
			// 注册 FeignClientsConfiguration
			registerClientConfiguration(registry, name,
					defaultAttrs.get("defaultConfiguration"));
		}
	}

	/**
	 * FeignClientsConfiguration
	 * @param metadata 注解元数据
	 * @param registry BeanDefinitionRegistry
	 */
	public void registerFeignClients(AnnotationMetadata metadata,
			BeanDefinitionRegistry registry) {
		// 获取组件扫描器
		ClassPathScanningCandidateComponentProvider scanner = getScanner();
		// 设置资源加载器
		scanner.setResourceLoader(this.resourceLoader);
		// 扫描包
		Set<String> basePackages;
		// 获取 @EnableFeignClients 注解元数据
		Map<String, Object> attrs = metadata
				.getAnnotationAttributes(EnableFeignClients.class.getName());
		// 创建 AnnotationTypeFilter，用于过滤指定注解，和 {@link java.lang.Class#isAnnotationPresent(Class)} 功能一致
		// 此位置是在指定包下过滤 @FeignClient 注解
		AnnotationTypeFilter annotationTypeFilter = new AnnotationTypeFilter(
				FeignClient.class);
		// 如果指定了 clients 属性，获取指定的 @FeignClient 类
		final Class<?>[] clients = attrs == null ? null
				: (Class<?>[]) attrs.get("clients");
		// 如果没有指定，则按照 AnnotationTypeFilter 进行过滤
		if (clients == null || clients.length == 0) {
			// 设置 AnnotationTypeFilter
			scanner.addIncludeFilter(annotationTypeFilter);
			// 获取需要扫描的包名
			basePackages = getBasePackages(metadata);
		}
		// 如果指定了 clients 属性
		else {
			final Set<String> clientClasses = new HashSet<>();
			basePackages = new HashSet<>();
			// 遍历 clients 指定的类型
			for (Class<?> clazz : clients) {
				// 添加 client 所在的包名
				basePackages.add(ClassUtils.getPackageName(clazz));
				clientClasses.add(clazz.getCanonicalName());
			}
			AbstractClassTestingTypeFilter filter = new AbstractClassTestingTypeFilter() {
				@Override
				protected boolean match(ClassMetadata metadata) {
					String cleaned = metadata.getClassName().replaceAll("\\$", ".");
					return clientClasses.contains(cleaned);
				}
			};
			scanner.addIncludeFilter(
					new AllTypeFilter(Arrays.asList(filter, annotationTypeFilter)));
		}
		// 遍历获取到的所有包名
		for (String basePackage : basePackages) {
			// 扫描指定包下符合过滤规则的 BeanDefinition
			Set<BeanDefinition> candidateComponents = scanner
					.findCandidateComponents(basePackage);
			// 遍历 BeanDefinition
			for (BeanDefinition candidateComponent : candidateComponents) {
				if (candidateComponent instanceof AnnotatedBeanDefinition) {
					// verify annotated class is an interface
					// 校验 @FeignClient 注解标记的类是否接口
					AnnotatedBeanDefinition beanDefinition = (AnnotatedBeanDefinition) candidateComponent;
					AnnotationMetadata annotationMetadata = beanDefinition.getMetadata();
					Assert.isTrue(annotationMetadata.isInterface(),
							"@FeignClient can only be specified on an interface");
					// 获取 @FeignClient 注解元数据
					Map<String, Object> attributes = annotationMetadata
							.getAnnotationAttributes(
									FeignClient.class.getCanonicalName());
					// 获取客户端名称，后续使用该名称作为 bean name
					String name = getClientName(attributes);
					// 获取 configuration, 进行自定义注册
					registerClientConfiguration(registry, name,
							attributes.get("configuration"));
					// 注册 FeignClient
					registerFeignClient(registry, annotationMetadata, attributes);
				}
			}
		}
	}

	/**
	 * 注册 FeignClient
	 * @param registry BeanDefinitionRegistry
	 * @param annotationMetadata FeignClient 注解元属性
	 * @param attributes 注解中属性值
	 */
	private void registerFeignClient(BeanDefinitionRegistry registry,
			AnnotationMetadata annotationMetadata, Map<String, Object> attributes) {
		// 获取类名
		String className = annotationMetadata.getClassName();
		// 创建 BeanDefinitionBuilder，基于 FeignClientFactoryBean 来生成代理类，注入容器中
		BeanDefinitionBuilder definition = BeanDefinitionBuilder
				.genericBeanDefinition(FeignClientFactoryBean.class);
		// 验证属性
		validate(attributes);
		// 添加属性值
		definition.addPropertyValue("url", getUrl(attributes));
		definition.addPropertyValue("path", getPath(attributes));
		String name = getName(attributes);
		definition.addPropertyValue("name", name);
		String contextId = getContextId(attributes);
		definition.addPropertyValue("contextId", contextId);
		definition.addPropertyValue("type", className);
		definition.addPropertyValue("decode404", attributes.get("decode404"));
		definition.addPropertyValue("fallback", attributes.get("fallback"));
		definition.addPropertyValue("fallbackFactory", attributes.get("fallbackFactory"));
		// 依赖注入类型，指定按照类型注入
		definition.setAutowireMode(AbstractBeanDefinition.AUTOWIRE_BY_TYPE);
		// 别名：contextId + FeignClient
		String alias = contextId + "FeignClient";
		// 获取 BeanDefinition
		AbstractBeanDefinition beanDefinition = definition.getBeanDefinition();

		boolean primary = (Boolean) attributes.get("primary"); // has a default, won't be
																// null
		// 设置 primary
		beanDefinition.setPrimary(primary);
		// 获取 qualifier
		String qualifier = getQualifier(attributes);
		// 如果指定 qualifier，则别名为 qualifier
		if (StringUtils.hasText(qualifier)) {
			alias = qualifier;
		}
		// 创建 BeanDefinitionHolder，指定 beanDefinition、className、alias
		BeanDefinitionHolder holder = new BeanDefinitionHolder(beanDefinition, className,
				new String[] { alias });
		// 注册
		BeanDefinitionReaderUtils.registerBeanDefinition(holder, registry);
	}

	/**
	 * 验证属性
	 * @param attributes 属性
	 */
	private void validate(Map<String, Object> attributes) {
		AnnotationAttributes annotation = AnnotationAttributes.fromMap(attributes);
		// This blows up if an aliased property is overspecified
		// FIXME annotation.getAliasedString("name", FeignClient.class, null);
		validateFallback(annotation.getClass("fallback"));
		validateFallbackFactory(annotation.getClass("fallbackFactory"));
	}

	/**
	 * 解析 name
	 * @param attributes 注解属性
	 * @return name
	 */
	/* for testing */ String getName(Map<String, Object> attributes) {
		// 依次匹配 serviceId 、 name 、value
		String name = (String) attributes.get("serviceId");
		if (!StringUtils.hasText(name)) {
			name = (String) attributes.get("name");
		}
		if (!StringUtils.hasText(name)) {
			name = (String) attributes.get("value");
		}
		// 替换占位符
		name = resolve(name);
		return getName(name);
	}

	private String getContextId(Map<String, Object> attributes) {
		String contextId = (String) attributes.get("contextId");
		if (!StringUtils.hasText(contextId)) {
			return getName(attributes);
		}

		contextId = resolve(contextId);
		return getName(contextId);
	}

	/**
	 * 解析属性值
	 * @param value 属性值
	 * @return 属性值
	 */
	private String resolve(String value) {
		// 如果属性值不为空，则从环境中获取属性值进行解析(占位符)
		if (StringUtils.hasText(value)) {
			return this.environment.resolvePlaceholders(value);
		}
		return value;
	}

	/**
	 * 获取 url
	 * @param attributes 注解属性
	 * @return url
	 */
	private String getUrl(Map<String, Object> attributes) {
		// 获取 url 属性，并解析
		String url = resolve((String) attributes.get("url"));
		return getUrl(url);
	}

	private String getPath(Map<String, Object> attributes) {
		String path = resolve((String) attributes.get("path"));
		return getPath(path);
	}

	/**
	 * 获取类路径下组件扫描器
	 * @return ClassPathScanningCandidateComponentProvider
	 */
	protected ClassPathScanningCandidateComponentProvider getScanner() {
		return new ClassPathScanningCandidateComponentProvider(false, this.environment) {
			@Override
			protected boolean isCandidateComponent(
					AnnotatedBeanDefinition beanDefinition) {
				boolean isCandidate = false;
				if (beanDefinition.getMetadata().isIndependent()) {
					if (!beanDefinition.getMetadata().isAnnotation()) {
						isCandidate = true;
					}
				}
				return isCandidate;
			}
		};
	}

	/**
	 * 获取注解中设置的需要扫描的包名
	 * @param importingClassMetadata 注解元数据
	 * @return 包名集合
	 */
	protected Set<String> getBasePackages(AnnotationMetadata importingClassMetadata) {
		// 获取 @EnableFeignClients 注解中设置的属性
		Map<String, Object> attributes = importingClassMetadata
				.getAnnotationAttributes(EnableFeignClients.class.getCanonicalName());
		// 包名
		Set<String> basePackages = new HashSet<>();
		// 遍历 value 属性
		for (String pkg : (String[]) attributes.get("value")) {
			if (StringUtils.hasText(pkg)) {
				basePackages.add(pkg);
			}
		}
		// 遍历 basePackages 属性
		for (String pkg : (String[]) attributes.get("basePackages")) {
			if (StringUtils.hasText(pkg)) {
				basePackages.add(pkg);
			}
		}
		// 获取 basePackageClasses，然后截取该 class 的包名
		for (Class<?> clazz : (Class[]) attributes.get("basePackageClasses")) {
			basePackages.add(ClassUtils.getPackageName(clazz));
		}
		// 如果获取的包为空，则添加默认包名
		// 默认包名为当前 @EnableFeignClients 标记的类所在的包名
		if (basePackages.isEmpty()) {
			basePackages.add(
					ClassUtils.getPackageName(importingClassMetadata.getClassName()));
		}
		return basePackages;
	}

	private String getQualifier(Map<String, Object> client) {
		if (client == null) {
			return null;
		}
		String qualifier = (String) client.get("qualifier");
		if (StringUtils.hasText(qualifier)) {
			return qualifier;
		}
		return null;
	}

	/**
	 * 获取客户端名称
	 * @param client @FeignClient 注解元数据
	 * @return 名称
	 */
	private String getClientName(Map<String, Object> client) {
		// 如果没有元数据，直接返回 null
		if (client == null) {
			return null;
		}
		// 获取 contextId
		String value = (String) client.get("contextId");
		// 如果没有指定 contextId， 则获取 value
		if (!StringUtils.hasText(value)) {
			value = (String) client.get("value");
		}
		// 如果没有指定 value, 则获取 name
		if (!StringUtils.hasText(value)) {
			value = (String) client.get("name");
		}
		// 如果以上都没指定，则获取 serviceId
		if (!StringUtils.hasText(value)) {
			value = (String) client.get("serviceId");
		}
		if (StringUtils.hasText(value)) {
			return value;
		}
		// 以上都没指定，抛异常
		throw new IllegalStateException("Either 'name' or 'value' must be provided in @"
				+ FeignClient.class.getSimpleName());
	}

	/**
	 * 注册 FeignClientsConfiguration 自定义配置信息，实际注册的是 FeignClientSpecification，FeignClientSpecification 中包含了 FeignClientsConfiguration 配置
	 * @param registry BeanDefinitionRegistry
	 * @param name bean name
	 * @param configuration FeignClientsConfiguration
	 */
	private void registerClientConfiguration(BeanDefinitionRegistry registry, Object name,
			Object configuration) {
		// 创建 BeanDefinitionBuilder，用于构建 BeanDefinition
		BeanDefinitionBuilder builder = BeanDefinitionBuilder
				.genericBeanDefinition(FeignClientSpecification.class);
		// 设置构造器参数，用于实例化 bean
		builder.addConstructorArgValue(name);
		builder.addConstructorArgValue(configuration);
		// 注册
		registry.registerBeanDefinition(
				name + "." + FeignClientSpecification.class.getSimpleName(),
				builder.getBeanDefinition());
	}

	@Override
	public void setEnvironment(Environment environment) {
		this.environment = environment;
	}

	/**
	 * Helper class to create a {@link TypeFilter} that matches if all the delegates
	 * match.
	 *
	 * @author Oliver Gierke
	 */
	private static class AllTypeFilter implements TypeFilter {

		private final List<TypeFilter> delegates;

		/**
		 * Creates a new {@link AllTypeFilter} to match if all the given delegates match.
		 * @param delegates must not be {@literal null}.
		 */
		AllTypeFilter(List<TypeFilter> delegates) {
			Assert.notNull(delegates, "This argument is required, it must not be null");
			this.delegates = delegates;
		}

		@Override
		public boolean match(MetadataReader metadataReader,
				MetadataReaderFactory metadataReaderFactory) throws IOException {

			for (TypeFilter filter : this.delegates) {
				if (!filter.match(metadataReader, metadataReaderFactory)) {
					return false;
				}
			}

			return true;
		}

	}

}
