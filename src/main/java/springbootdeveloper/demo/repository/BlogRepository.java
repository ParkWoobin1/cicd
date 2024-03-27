package springbootdeveloper.demo.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import springbootdeveloper.demo.domain.Article;

public interface BlogRepository extends JpaRepository<Article, Long> {
}
