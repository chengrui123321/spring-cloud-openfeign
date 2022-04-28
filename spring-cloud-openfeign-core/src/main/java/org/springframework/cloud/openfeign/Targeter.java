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

import feign.Feign;
import feign.Target;

/**
 * @author Spencer Gibb
 *
 * 目标执行接口，根据 {@link FeignClientFactoryBean#getObject()} 创建代理类
 */
interface Targeter {

	/**
	 * 获取目标对象代理类
	 * @param factory FeignClientFactoryBean
	 * @param feign Feign.Builder
	 * @param context FeignContext
	 * @param target Target
	 * @return
	 * @param <T>
	 */
	<T> T target(FeignClientFactoryBean factory, Feign.Builder feign,
			FeignContext context, Target.HardCodedTarget<T> target);

}
