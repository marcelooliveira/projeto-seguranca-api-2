namespace MedVoll.Web.Dtos
{
    public interface IPaginatedList
    {
        int TotalItemCount { get; }
        int PageNumber { get; }
        int PageSize { get; }
        int TotalPages { get; }
        bool HasPreviousPage { get; }
        bool HasNextPage { get; }
    }
}


