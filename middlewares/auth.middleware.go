package middlewares

import (
	res "github.com/srv-cashpay/util/s/response"

	"github.com/golang-jwt/jwt/v4"
	"github.com/labstack/echo/v4"
)

func AuthorizeJWT(jwtService JWTService) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			authHeader := c.Request().Header.Get("Authorization")
			if authHeader == "" {
				return res.ErrorBuilder(&res.ErrorConstant.Unauthorized, nil).Send(c)
			}

			// ValidateToken returns the token, userID, and an error
			token, _, err := jwtService.ValidateToken(authHeader)
			if err != nil {
				return res.ErrorBuilder(&res.ErrorConstant.Unauthorized, err).Send(c)
			}

			// Now you have the token and userID for further processing
			if token.Valid {
				claims := token.Claims.(jwt.MapClaims)

				// Extract the user name from the JWT claims
				userName, ok := claims["name"].(string)
				if !ok {
					return res.ErrorBuilder(&res.ErrorConstant.BadRequest, &res.Error{}).Send(c)
				}

				id, ok := claims["id"].(string)
				if !ok {
					return res.ErrorBuilder(&res.ErrorConstant.BadRequest, &res.Error{}).Send(c)
				}

				// Set the user name as the CreatedBy value in the context
				c.Set("CreatedBy", userName)

				// Set the user name as the CreatedBy value in the context
				c.Set("UpdatedBy", userName)

				// Set the user name as the CreatedBy value in the context
				c.Set("DeletedBy", userName)

				c.Set("MerchatId", userName)

				c.Set("UserId", id)

				c.Set("AdminId", id)

				c.Set("LikeId", id)

				return next(c)
			} else {
				return res.ErrorBuilder(&res.ErrorConstant.BadRequest, &res.Error{}).Send(c)
			}
		}
	}
}

func ApiKeyMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		apiKey := c.Request().Header.Get("X-API-Key")
		if apiKey != "3f=Pr#g1@RU-nw=30" {
			return echo.ErrUnauthorized
		}
		return next(c)
	}
}
