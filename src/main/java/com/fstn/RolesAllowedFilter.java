/**
Copy paste of  google exemple
**/

@Provider
@Priority(Priorities.AUTHORIZATION)
public class AuthenticationFilterForJWTTokenBasedOnEnginePrincipal implements ContainerRequestFilter
{

    public static final String USER_CONTEXT_MISSING = "User context is missing, please verify request headers";
    public static final String USER_HAS_NO_PRIVILEGES = "User has not privileges";
    @Context
    private ResourceInfo resourceInfo;

    @Context
    private HttpServletRequest httpRequest;

    @SuppressWarnings("UnusedCatchParameter")
    @Override
    public void filter(ContainerRequestContext requestContext) throws IOException {
        // Get the HTTP Authorization header from the request
        if (SecurityUtils.isSecurityEnabled()) {
            Class<?> resourceClass = resourceInfo.getResourceClass();

            Set<String> classRoles = extractRoles(resourceClass);

            Method resourceMethod = resourceInfo.getResourceMethod();
            Set<String> methodRoles = extractRoles(resourceMethod);

            String authorization = AuthorizationUtils.getFromContext(requestContext);
            UserContext userContext = UserContextUtils.getUserContextFromAuthorization(authorization);

            List<String> unauthorizedReasons = new ArrayList<>();

            if (!resourceClass.isAnnotationPresent(PermitAll.class) &&
                methodRoles.isEmpty() &&
                classRoles.isEmpty()) {
                return;
            }

            //has secured annotation, check if request has been authenticated
            try {

                if (Objects.isNull(userContext.getName())) {
                    requestContext.abortWith(
                        Response.status(Response.Status.UNAUTHORIZED)
                                .entity(USER_CONTEXT_MISSING)
                                .build
                            ());
                }

                requestContext.setSecurityContext(new SecurityContext()
                {
                    @Override
                    public Principal getUserPrincipal() {
                        return userContext.getPrincipal();
                    }

                    @Override
                    public boolean isUserInRole(String role) {
                        if (Objects.isNull(userContext.getPrivileges())) {
                            unauthorizedReasons.add(USER_HAS_NO_PRIVILEGES);
                            return false;
                        }
                        boolean isUserInRoleResult = userContext.getPrivileges()
                                          .stream()
                                          .filter(Objects::nonNull)
                                          .anyMatch(privilege -> Objects.equals(privilege.getName(), role));
                        if(!isUserInRoleResult){
                            unauthorizedReasons.add("Privilege "+role+" is missing, current user privileges are: ["
                                                        +userContext.getPrivileges().stream()
                                                                    .map(privilege ->privilege.getName())
                                                                    .collect(Collectors.joining(","))+"]");
                        }
                        return isUserInRoleResult;
                    }

                    @Override
                    public boolean isSecure() {
                        return true;
                    }

                    @Override
                    public String getAuthenticationScheme() {
                        return null;
                    }
                });
                if (resourceClass.isAnnotationPresent(PermitAll.class) &&
                    methodRoles.isEmpty()) {
                    return;
                }
                if (!methodRoles.isEmpty()) {
                    for (String role : methodRoles) {
                        if (requestContext.getSecurityContext().isUserInRole(role)) {
                            return;
                        }
                    }
                }
                if ((!classRoles.isEmpty())) {
                    for (String role : classRoles) {
                        if (requestContext.getSecurityContext().isUserInRole(role)) {
                            return;
                        }
                    }
                }
                requestContext.abortWith(
                    Response.status(Response.Status.FORBIDDEN)
                            .entity(unauthorizedReasons).build());
            } catch (Exception e) {
                requestContext.abortWith(
                    Response.status(Response.Status.FORBIDDEN).build());
            }
        }
    }

    // Extract the roles from the annotated element
    private Set<String> extractRoles(AnnotatedElement annotatedElement) {

        if (Objects.isNull(annotatedElement)) {
            return new HashSet<>();

        } else {
            RolesAllowed rolesAllowed = annotatedElement
                .getAnnotation(RolesAllowed.class);
            Set<String> roles = new HashSet<>();
            if (Objects.isNull(rolesAllowed)) {
                return roles;
            } else {
                String[] allowedRoles = rolesAllowed.value();
                return new HashSet<>(Arrays.asList(allowedRoles));
            }
        }
    }

}
