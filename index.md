---
layout: home
title: Home
---

{% assign articles = site.pages | where_exp: "item", "item.path contains 'notes/'" | sort: "date" | reverse %}
{% for article in articles %}
<article>
	<h2><a href="{{ article.url | relative_url }}">{{ article.title }}</a></h2>
	<p class="text-small text-grey-dk-100">{{ article.date | date: "%b %-d, %Y" }}</p>
	<p>{{ article.content | split: '<!--more-->' | first | strip_html | strip_newlines | truncatewords: 60 }}</p>
	<p><a href="{{ article.url | relative_url }}">Read more</a></p>
</article>
{% endfor %}