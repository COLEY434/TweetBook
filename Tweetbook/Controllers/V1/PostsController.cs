using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Tweetbook.Contracts.V1;
using Tweetbook.Contracts.V1.Response;
using Tweetbook.Contracts.V1.Request;
using Tweetbook.Domain;
using Tweetbook.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Tweetbook.Extensions;

namespace Tweetbook.Controllers.V1
{
     [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    [ApiController]
    public class PostsController : Controller
    {
        private readonly IPostService _postService;

        
        public PostsController(IPostService postService)
        {
            _postService = postService;
        }

        [HttpGet(ApiRoutes.posts.GetAll)]
        public async Task<IActionResult> GetAll()
        {
            return Ok(await _postService.GetPostsAsync());
        }

        [HttpPut(ApiRoutes.posts.Update)]
        public async Task<IActionResult> Update([FromRoute] Guid postId, [FromBody] UpdatePostRequest request)
        {
            var userOwnPost = await _postService.userOwnPostAsync(postId, HttpContext.GetUserId());

            if (!userOwnPost)
            {
                return BadRequest(new { error = "You do not own this post" });
            }
            var post = await _postService.GetPostByIdAsync(postId);
            post.Name = request.Name;

            var updated = await  _postService.UpdatePostAsync(post);

            if (updated)
                return Ok(post);

            return NotFound();
        }

        [HttpGet(ApiRoutes.posts.Get)]
        public async Task<IActionResult> Get([FromRoute] Guid postId)
        {
            var post = await _postService.GetPostByIdAsync(postId);

            if (post == null)
                return NotFound();
            return Ok(post);
        }

        [HttpDelete(ApiRoutes.posts.Delete)]
        public async Task<IActionResult> Delete([FromRoute] Guid postId)
        {
            var userOwnPost = await _postService.userOwnPostAsync(postId, HttpContext.GetUserId());

            if (!userOwnPost)
            {
                return BadRequest(new { error = "You do not own this post" });
            }
            
            var deleted = await _postService.DeletePostAsync(postId);

            if (deleted)
                return NoContent();

            return NotFound();
        }

        [HttpPost(ApiRoutes.posts.Create)]
        public async Task<IActionResult> Create([FromBody] CreatePostRequest createPostRequest)
        {
            var post = new post
            {
                Name = createPostRequest.Name,
                UserId = HttpContext.GetUserId()
            
            };

            await _postService.CreatePostAsync(post);

            var baseUrl = $"{HttpContext.Request.Scheme}://{HttpContext.Request.Host.ToUriComponent()}";
            var locationUri = baseUrl + "/" + ApiRoutes.posts.Get.Replace("{postId}", post.Id.ToString());

            var response = new PostResponse { Id = post.Id };
            return Created(locationUri, response);

        }

    }
}