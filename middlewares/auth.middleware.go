package middlewares

import (
	"net/http"

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
				refreshToken := c.Request().Header.Get("Authorization") // Expect refresh token in the header
				if refreshToken == "" {
					return echo.NewHTTPError(http.StatusUnauthorized, "Missing refresh token")
				}
				_, userID, err := jwtService.ValidateToken(refreshToken)
				if err != nil {
					return echo.NewHTTPError(http.StatusUnauthorized, "Invalid refresh token")
				}

				accessToken, err := jwtService.GenerateToken(userID, "name", "merchant_id")
				if err != nil {
					return echo.NewHTTPError(http.StatusInternalServerError, "Error generating new access token")
				}

				c.Response().Header().Set("Authorization", "Bearer "+accessToken)

			} else {
				// Valid token access
				claims := token.Claims.(jwt.MapClaims)

				// Extract user information from claims
				userName, ok := claims["name"].(string)
				if !ok {
					return res.ErrorBuilder(&res.ErrorConstant.BadRequest, &res.Error{}).Send(c)
				}

				id, ok := claims["id"].(string)
				if !ok {
					return res.ErrorBuilder(&res.ErrorConstant.BadRequest, &res.Error{}).Send(c)
				}

				merchantId, ok := claims["merchant"].(string)
				if !ok {
					return res.ErrorBuilder(&res.ErrorConstant.BadRequest, &res.Error{}).Send(c)
				}

				// Set user info in context
				c.Set("CreatedBy", userName)
				c.Set("UpdatedBy", userName)
				c.Set("DeletedBy", userName)
				c.Set("MerchantId", merchantId)
				c.Set("UserId", id)
				c.Set("AdminId", id)
				c.Set("LikeId", id)
			}

			// Lanjutkan ke handler berikutnya
			return next(c)
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
