using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Tweetbook.Domain;

namespace Tweetbook.Services
{
    public interface IPostService
    {
        Task<bool> CreatePostAsync(post Post);
        Task<List<post>> GetPostsAsync();

        Task<post> GetPostByIdAsync(Guid postId);

        Task<bool> UpdatePostAsync(post postToUpdate);

        Task<bool> DeletePostAsync(Guid postId);

        Task<bool> userOwnPostAsync(Guid postId, string userId);
    }
}
