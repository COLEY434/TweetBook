using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Tweetbook.Contracts.V1;
using Tweetbook.Contracts.V1.Request;
using Tweetbook.Contracts.V1.Response;
using Tweetbook.Services;

namespace Tweetbook.Controllers.V1
{
    
    [ApiController]
    public class IdentityController : ControllerBase
    {
        private readonly IIdentityService _identityService;

        public IdentityController(IIdentityService identityService)
        {
            _identityService = identityService;
        }

        [HttpPost(ApiRoutes.Identity.Register)]
        public async Task<IActionResult> Register([FromBody] UserRegistrationRequest request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(new AuthFailedResponse 
                { 
                    ErrorMessages = ModelState.Values.SelectMany(x => x.Errors.Select(xx => xx.ErrorMessage))
                });
            }
            try
            {
                var authResponse = await _identityService.RegisterAsync(request.Email, request.Password);

                if (!authResponse.Success)
                {
                    return BadRequest(new AuthFailedResponse
                    {
                        ErrorMessages = authResponse.ErrorMessage
                    });
                }
                return Ok(new AuthSuccessResponse
                {
                    Token = authResponse.Token,
                    RefreshToken = authResponse.RefreshToken
                });
            }
            catch(Exception ex)
            {
                return Ok(ex.Message);
            }
           
        }



        [HttpPost(ApiRoutes.Identity.Login)]
        public async Task<IActionResult> Login([FromBody] UserLoginRequest request)
        {
            try
            {
                var authResponse = await _identityService.LoginAsync(request.Email, request.Password);

                if (!authResponse.Success)
                {
                    return BadRequest(new AuthFailedResponse
                    {
                        ErrorMessages = authResponse.ErrorMessage
                    });
                }
                return Ok(new AuthSuccessResponse
                {
                    Token = authResponse.Token,
                    RefreshToken = authResponse.RefreshToken
                });
            }
            catch (Exception ex)
            {
                return Ok(ex.Message);
            }

        }

        [HttpPost(ApiRoutes.Identity.Refresh)]
        public async Task<IActionResult> Refresh([FromBody] RefreshTokenRequest request)
        {
            try
            {
                var authResponse = await _identityService.RefreshTokenAsync(request.Token, request.RefreshToken);

                if (!authResponse.Success)
                {
                    return BadRequest(new AuthFailedResponse
                    {
                        ErrorMessages = authResponse.ErrorMessage
                    });
                }
                return Ok(new AuthSuccessResponse
                {
                    Token = authResponse.Token,
                    RefreshToken = authResponse.RefreshToken
                });
            }
            catch (Exception ex)
            {
                return Ok(ex.Message);
            }

        }
    }
}