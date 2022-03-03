<%@page session="false" pageEncoding="utf-8" %>
<%@taglib prefix="sling" uri="http://sling.apache.org/taglibs/sling/1.2" %>
<%@taglib prefix="cpn" uri="http://sling.composum.com/cpnl/1.0" %>
<%@taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<sling:defineObjects/>
Page <%= resource.getPath() %> is rendered for <%= request.getUserPrincipal().getName() %>.

<form action="/content/test/composum/authtest/fresh" method="POST" enctype="multipart/form-data">
    <input type="text" name="title" value="blu">
    <input type="text" name="text" value="bluf">
    <input type="submit">
</form>
