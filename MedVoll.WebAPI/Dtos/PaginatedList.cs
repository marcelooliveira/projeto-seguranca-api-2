using Microsoft.EntityFrameworkCore;

namespace MedVoll.Web.Dtos
{
    public class PaginatedList<T> : List<T>, IPaginatedList
    {
        public int TotalItemCount { get; }
        public int PageNumber { get; private set; }
        public int PageSize { get; }
        public int TotalPages { get; private set; }
        public bool HasPreviousPage => PageNumber > 1;
        public bool HasNextPage => PageNumber < TotalPages;

        public PaginatedList(List<T> items, int totalItemCount, int pageNumber, int pageSize)
        {
            TotalItemCount = totalItemCount;
            PageNumber = pageNumber;
            PageSize = pageSize;
            TotalPages = (int)Math.Ceiling(totalItemCount / (double)pageSize);

            AddRange(items);
        }

        public static async Task<PaginatedList<T>> CreateAsync(IQueryable<T> source, int pageIndex, int pageNumber)
        {
            var totalItemCount = await source.CountAsync();
            var items = await source.Skip((pageIndex - 1) * pageNumber).Take(pageNumber).ToListAsync();
            return new PaginatedList<T>(items, totalItemCount, pageIndex, pageNumber);
        }
    }
}


