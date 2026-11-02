package storefront

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/bootdotdev/learn-web-security/internal/database/dbgen"
)

type Product struct {
	ID             int64
	Name           string
	Description    string
	ImagePath      string
	PriceCents     int64
	CostCents      int64
	InventoryCount int64
	IsActive       bool
	CreatedAt      string
}

type Review struct {
	ID           int64
	UserID       int64
	ProductID    int64
	ProductName  string
	ReviewerName string
	Rating       int64
	Body         string
	CreatedAt    string
	UpdatedAt    string
}

type Store struct {
	database *sql.DB
	queries  *dbgen.Queries
}

func NewStore(database *sql.DB) *Store {
	return &Store{database: database, queries: dbgen.New(database)}
}

func (store *Store) ListProducts(ctx context.Context, maxResults int64) ([]Product, error) {
	rows, err := store.queries.ListActiveProducts(ctx, maxResults)
	if err != nil {
		return nil, fmt.Errorf("list products: %w", err)
	}
	return mapProducts(rows), nil
}

func (store *Store) SearchProducts(ctx context.Context, query string, maxResults int64) ([]Product, error) {
	rows, err := store.queries.SearchActiveProducts(ctx, dbgen.SearchActiveProductsParams{
		Pattern:    "%" + query + "%",
		MaxResults: maxResults,
	})
	if err != nil {
		return nil, fmt.Errorf("search products: %w", err)
	}
	return mapProducts(rows), nil
}

func (store *Store) FindProduct(ctx context.Context, productID int64) (Product, bool, error) {
	row, err := store.queries.GetActiveProduct(ctx, productID)
	if err != nil {
		if err == sql.ErrNoRows {
			return Product{}, false, nil
		}
		return Product{}, false, fmt.Errorf("find product: %w", err)
	}
	return mapProduct(row), true, nil
}

func (store *Store) ListReviews(ctx context.Context, productID int64) ([]Review, error) {
	rows, err := store.queries.ListReviewsForProduct(ctx, productID)
	if err != nil {
		return nil, fmt.Errorf("list product reviews: %w", err)
	}
	reviews := make([]Review, 0, len(rows))
	for _, row := range rows {
		reviews = append(reviews, Review{
			ID:           row.ID,
			UserID:       row.UserID,
			ProductID:    row.ProductID,
			ProductName:  row.ProductName,
			ReviewerName: row.ReviewerName,
			Rating:       row.Rating,
			Body:         row.Body,
			CreatedAt:    row.CreatedAt,
			UpdatedAt:    row.UpdatedAt,
		})
	}
	return reviews, nil
}

func mapProducts(rows []dbgen.Product) []Product {
	products := make([]Product, 0, len(rows))
	for _, row := range rows {
		products = append(products, mapProduct(row))
	}
	return products
}

func mapProduct(row dbgen.Product) Product {
	return Product{
		ID:             row.ID,
		Name:           row.Name,
		Description:    row.Description,
		ImagePath:      row.ImagePath,
		PriceCents:     row.PriceCents,
		CostCents:      row.CostCents,
		InventoryCount: row.InventoryCount,
		IsActive:       row.IsActive == 1,
		CreatedAt:      row.CreatedAt,
	}
}

func scanProducts(rows *sql.Rows) ([]Product, error) {
	products := make([]Product, 0)
	for rows.Next() {
		var product Product
		var active int64
		if err := rows.Scan(&product.ID, &product.Name, &product.Description, &product.ImagePath, &product.PriceCents, &product.CostCents, &product.InventoryCount, &active, &product.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan product: %w", err)
		}
		product.IsActive = active == 1
		products = append(products, product)
	}
	return products, rows.Err()
}
