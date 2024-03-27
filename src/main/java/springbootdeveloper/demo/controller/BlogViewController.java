package springbootdeveloper.demo.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import springbootdeveloper.demo.domain.Article;
import springbootdeveloper.demo.dto.ArticleListViewResponse;
import springbootdeveloper.demo.dto.ArticleViewResponse;
import springbootdeveloper.demo.service.BlogService;
import java.util.List;

@RequiredArgsConstructor
@Controller
public class BlogViewController {

    private final BlogService blogService;

    @GetMapping("/articles")
    public String getArticles(Model model) {
        List<ArticleListViewResponse> articles = blogService.findAll()
                .stream()
                .map(ArticleListViewResponse::new)
                .toList();
        model.addAttribute("articles", articles);//블로그객체저장

        return "articleList";//resource/templates/articleList.html으로 뷰지정
    }

    @GetMapping("/articles/{id}")
    public String getArticle(@PathVariable Long id, Model model) {
        Article article = blogService.findById(id);
        model.addAttribute("article", new ArticleViewResponse(article));

        return "article";
    }

    @GetMapping("/new-article")
    //id키를 가진 쿼리 파라미터 값을 id변수에 매핑
    public String newArticle(@RequestParam(required = false) Long id, Model model) {
        if (id == null) { //id가 없으면 생성
            model.addAttribute("article", new ArticleViewResponse());
        } else { //id가 있으면 수정
            Article article = blogService.findById(id);
            model.addAttribute("article", new ArticleViewResponse(article));
        }

        return "newArticle";
    }

}
